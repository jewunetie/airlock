# NOT YET FUNCTIONAL. No tagged release exists in this repository, so the
# `url` below 404s and the `sha256` below is a placeholder, not a real
# digest: `brew install --formula Formula/airlock.rb` fails today, on
# purpose rather than silently, on either the download or the checksum.
# This formula activates on the first tagged release. To make it live:
#   1. Cut a `vX.Y.Z` git tag matching airlock.py's __version__.
#   2. Compute the release tarball's digest:
#        curl -L https://github.com/jewunetie/airlock/archive/refs/tags/vX.Y.Z.tar.gz \
#          | shasum -a 256
#   3. Replace both the `url` version and the `sha256` value below with
#      the real ones, and remove this banner.
# README.md's Install section must not call Homebrew a working path until
# this is done; keep the two in sync.
class Airlock < Formula
  desc "Guarded local model that answers questions over one directory via MCP"
  homepage "https://github.com/jewunetie/airlock"
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
