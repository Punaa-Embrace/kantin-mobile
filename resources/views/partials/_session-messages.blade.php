  @if (session('success'))
      <div class="bg-green-100/80 border border-green-400 text-green-700 px-4 py-3 rounded-md relative mb-4"
          role="alert">
          {{ session('success') }}
      </div>
  @endif
  @if (session('error'))
      <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded-md relative mb-4" role="alert">
          {{ session('error') }}
      </div>
  @endif
