class Airlock < Formula
  desc "Guarded local model that answers questions over one directory via MCP"
  homepage "https://github.com/jewunetie/airlock"
  # No tagged release exists yet. This URL and sha256 are placeholders for
  # the first `vX.Y.Z` tag; update both together, and keep the version
  # below in step with airlock.py's __version__, when that tag is cut.
  url "https://github.com/jewunetie/airlock/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  license "MIT"

  depends_on "uv" => :build
  depends_on "python@3.11"

  # airlock pulls torch and transformers (~2.6GB with model weights),
  # already declared once in pyproject.toml (see tests/test_packaging.py
  # for why that list must stay the single copy of the version bounds, not
  # duplicated as `resource` blocks here too, which is the normal Homebrew
  # Python pattern but would be a third place for the same dependency list
  # to drift). `uv pip install` resolves and installs into a private
  # venv from that one declaration instead.
  def install
    venv = libexec
    system "uv", "venv", "--python", formula_opt_bin("python@3.11")/"python3.11", venv
    system "uv", "pip", "install", "--python", venv/"bin/python", "."
    bin.install_symlink venv/"bin/airlock"
  end

  test do
    assert_match "airlock #{version}", shell_output("#{bin}/airlock --version")
  end
end
