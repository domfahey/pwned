class Pwned < Formula
  include Language::Python::Virtualenv

  desc "Command-line interface and Python client for Have I Been Pwned"
  homepage "https://github.com/domfahey/pwned"
  url "https://github.com/domfahey/pwned/releases/download/v0.4.0/pwned-0.4.0.tar.gz"
  sha256 "03bdff61fb9bd7b9301f7272fcb0a4d002a6eb4c1b0a4087555d9bdfee5caf7b"
  license "MIT"

  depends_on "python@3.12"

  def install
    virtualenv_install_with_resources
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/pwned --version")
  end
end
# NOTE: Copy this file into a `homebrew-tap` repository (e.g. `Formula/pwned.rb`)
# and add `resource` blocks for runtime dependencies (e.g. via `homebrew-pypi-poet`).
