defmodule Mix.Tasks.Compile.ETEA do

  def run(_) do
    File.mkdir("priv")
    {exec, args} = case :os.type do
      {:win32, _} ->
        {"nmake", ["/F", "Makefile.win", "priv\\etea_nif.dll"]}
      {:unix, :freebsd} ->
        {"gmake", ["priv/etea_nif.so"]}
      {:unix, :openbsd} ->
        {"gmake", ["priv/etea_nif.so"]}
      _ ->
        {"make", ["priv/etea_nif.so"]}
    end

    if System.find_executable(exec) do
      build(exec, args)
      Mix.Project.build_structure
      :ok
    else
      nocompiler_error(exec)
    end
  end

  def build(exec, args) do
    {result, error_code} = System.cmd(exec, args, stderr_to_stdout: true)
    IO.binwrite result
    if error_code != 0, do: build_error(exec)
  end

  defp nocompiler_error("nmake") do
    raise Mix.Error, message: nocompiler_message("nmake") <> windows_message()
  end
  defp nocompiler_error(exec) do
    raise Mix.Error, message: nocompiler_message(exec) <> nix_message()
  end

  defp build_error("nmake") do
    raise Mix.Error, message: build_message() <> windows_message()
  end
  defp build_error(_) do
    raise Mix.Error, message: build_message() <> nix_message()
  end

  defp nocompiler_message(exec) do
    """
    Could not find the program `#{exec}`.
    You will need to install the C compiler `#{exec}` to be able to build
    ETEA.
    """
  end

  defp build_message do
    """
    Could not compile ETEA.
    Please make sure that you are using Erlang / OTP version 17.0 or later
    and that you have a C compiler installed.
    """
  end

  defp windows_message do
    """
    One option is to install a recent version of Visual Studio (the
    free Community edition will be enough for this task). Then try running
    `mix deps.compile ETEA` from the `Developer Command Prompt`.
    If you are using 64-bit erlang, you might need to run the command
    `vcvarsall.bat amd64` in the Visual Studio {version}\VC directory
    before running `mix deps.compile`.
    See: https://msdn.microsoft.com/en-us/library/x4d2c09s.aspx
    If you are using Visual Studio 2015, you need to install the C++ build
    tools before running the `vcvarsall.bat amd64`. Do this by going to
    "Create New Project" and select "C++" to prompt to install the
    required dependencies.
    See: https://msdn.microsoft.com/en-us/library/60k1461a.aspx
    """
  end

  defp nix_message do
    """
    Please follow the directions below for the operating system you are
    using:
    Mac OS X: You need to have gcc and make installed. Try running the
    commands `gcc --version` and / or `make --version`. If these programs
    are not installed, you will be prompted to install them.
    Linux: You need to have gcc and make installed. If you are using
    Ubuntu or any other Debian-based system, install the packages
    `build-essential`. Also install `erlang-dev` package if not
    included in your Erlang/OTP version.
    """
  end
end

defmodule ETEA.Mixfile do
  use Mix.Project

  def project do
    [app: :etea,
     version: "0.1.0",
     elixir: ">= 1.0.0 and < 2.0.0",
     build_embedded: Mix.env == :prod,
     start_permanent: Mix.env == :prod,
     compilers: [:ETEA, :elixir, :app],
     deps: deps(),
     description: description(),
     package: package()
    ]
  end

  def application do
    [applications: [:logger]]
  end

  defp deps do
    []
  end

  defp description do
    """
    A library used to encrypt/decrypt data using the TEA algorithm.
    """
  end

  defp package do
    [
      files: ["lib", "src", "mix.exs", "Makefile*", "README.md", "LICENSE"],
      maintainers: ["Michael Martin"],
      licenses: ["MIT"],
      links: %{"GitHub" => "https://github.com/instantchannel/eTEA"}
    ]
  end

end
