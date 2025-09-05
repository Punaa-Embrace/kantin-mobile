<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\Otp;
use App\Models\User;
use App\Notifications\OtpNotification;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use Str;

class AuthController extends Controller
{
    public function showLoginForm()
    {
        return view('auth.login');
    }

    public function showRegisterForm()
    {
        return view('auth.register');
    }

    public function showForgetPasswordForm()
    {
        return view('auth.forget-password');
    }

    public function showOtpForm(Request $request)
    {
        if (!$request->session()->has('otp_identifier') || !$request->session()->has('otp_type')) {
            return redirect()->route('login')->with('error', 'Sesi tidak valid. Silakan coba lagi.');
        }
        return view('auth.otp');
    }

    private function generateAndSendOtp(User $user, string $type)
    {
        $otp = Otp::updateOrCreate(
            ['identifier' => $user->email, 'type' => $type],
            [
                'code' => random_int(100000, 999999),
                'expires_at' => Carbon::now()->addMinutes(5)
            ]
        );

        $user->notify(new OtpNotification($otp));
    }

    public function register(Request $request)
    {
        $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'phone' => 'required|string|min:10|max:15|unique:users,phone',
            'password' => 'required|string|min:8|confirmed',
        ]);

        $otp = Otp::updateOrCreate(
            ['identifier' => $request->email, 'type' => 'registration'],
            [
                'code' => random_int(100000, 999999),
                'expires_at' => Carbon::now()->addMinutes(5)
            ]
        );

        Notification::route('whatsapp', $request->phone)->notify(new OtpNotification($otp));

        $request->session()->put('registration_data', $request->only('name', 'email', 'phone', 'password'));
        $request->session()->put('otp_identifier', $request->email);
        $request->session()->put('otp_type', 'registration');
        
        return redirect()->route('otp.form')->with('status', 'Kode OTP telah dikirim ke nomor WhatsApp Anda.');
    }

    public function verifyOtp(Request $request)
    {
        $request->validate(['code' => 'required|string|min:6|max:6']);

        $identifier = $request->session()->get('otp_identifier');
        $type = $request->session()->get('otp_type');

        if (!$identifier || !$type) {
            return redirect()->route('login')->with('error', 'Sesi Anda telah berakhir. Silakan coba lagi.');
        }

        $otp = Otp::where('identifier', $identifier)
                    ->where('type', $type)
                    ->where('code', $request->code)
                    ->where('expires_at', '>', Carbon::now())
                    ->first();

        if (!$otp) {
            return back()->with('error', 'Kode OTP tidak valid atau telah kedaluwarsa.');
        }

        if ($type === 'registration') {
            $userData = $request->session()->get('registration_data');
            $user = User::create([
                'name' => $userData['name'],
                'email' => $userData['email'],
                'phone' => $userData['phone'],
                'password' => Hash::make($userData['password']),
                'role' => 'student',
                'email_verified_at' => now(),
            ]);
            
            Auth::login($user);

            $otp->delete();
            $request->session()->forget(['registration_data', 'otp_identifier', 'otp_type']);
            
            return redirect()->route('dashboard');

        } elseif ($type === 'password_reset') {
            $request->session()->put('password_reset_token', Str::random(40));
            $otp->delete();
            
            return redirect()->route('password.reset');
        }

        return redirect()->route('login')->with('error', 'Terjadi kesalahan. Silakan coba lagi.');
    }

    public function sendResetOtp(Request $request)
    {
        // MODIFIED: Validate phone number instead of email
        $request->validate([
            'phone' => 'required|string|exists:users,phone',
        ]);

        // MODIFIED: Find user by phone number
        $user = User::where('phone', $request->phone)->firstOrFail();

        // The rest of the logic works perfectly because our helper uses the User object
        $this->generateAndSendOtp($user, 'password_reset');

        // IMPORTANT: We still use the email as the unique identifier for the session
        $request->session()->put('otp_identifier', $user->email);
        $request->session()->put('otp_type', 'password_reset');

        return redirect()->route('otp.form')->with('status', 'Kode OTP untuk reset password telah dikirim.');
    }

     public function resendOtp(Request $request)
    {
        $identifier = $request->session()->get('otp_identifier');
        $type = $request->session()->get('otp_type');

        if (!$identifier || !$type) {
            return redirect()->route('login')->with('error', 'Sesi Anda telah berakhir. Silakan coba lagi.');
        }

        $existingOtp = Otp::where('identifier', $identifier)->where('type', $type)->first();

        if ($existingOtp && $existingOtp->updated_at->addMinute()->isFuture()) {
            $secondsLeft = $existingOtp->updated_at->addMinute()->diffInSeconds(now());
            return back()->with('error', "Harap tunggu {$secondsLeft} detik lagi sebelum meminta kode baru.");
        }
        
        $otp = Otp::updateOrCreate(
            ['identifier' => $identifier, 'type' => $type],
            [
                'code' => random_int(100000, 999999),
                'expires_at' => Carbon::now()->addMinutes(5)
            ]
        );

        if ($type === 'registration') {
            $phone = $request->session()->get('registration_data')['phone'];
            Notification::route('whatsapp', $phone)->notify(new OtpNotification($otp));
        } elseif ($type === 'password_reset') {
            $user = User::where('email', $identifier)->first();
            if ($user && $user->phone) {
                $user->notify(new OtpNotification($otp));
            } else {
                return back()->with('error', 'Tidak dapat menemukan nomor telepon untuk mengirim ulang OTP.');
            }
        }
        
        return back()->with('status', 'Kode OTP baru telah berhasil dikirim.');
    }

    public function showNewPasswordForm(Request $request)
    {
        if (!$request->session()->has('password_reset_token')) {
            return redirect()->route('password.request')->with('error', 'Token tidak valid. Silakan minta link reset baru.');
        }
        return view('auth.new-password');
    }
    
    public function resetPassword(Request $request)
    {
        if (!$request->session()->has('password_reset_token')) {
            return redirect()->route('password.request')->with('error', 'Sesi reset password telah berakhir.');
        }

        $request->validate(['password' => 'required|string|min:8|confirmed']);
        
        $email = $request->session()->get('otp_identifier');
        $user = User::where('email', $email)->firstOrFail();

        $user->password = Hash::make($request->password);
        $user->save();

        $request->session()->forget(['otp_identifier', 'otp_type', 'password_reset_token']);
        
        Auth::login($user);

        return redirect()->route('dashboard')->with('status', 'Kata sandi Anda berhasil diubah!');
    }

    public function login(Request $request)
    {
        $credentials = $request->validate([
            'email' => 'required|email',
            'password' => 'required',
        ]);

        if (Auth::attempt($credentials)) {
            $request->session()->regenerate();
            return redirect()->intended('dashboard');
        }

        return back()->withErrors(['email' => 'Email atau kata sandi yang Anda masukkan salah.'])->onlyInput('email');
    }

    public function logout(Request $request)
    {
        Auth::logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();
        return redirect('/');
    }
}
