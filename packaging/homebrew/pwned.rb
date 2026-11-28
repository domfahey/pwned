class Pwned < Formula
  include Language::Python::Virtualenv

  desc "Command-line interface and Python client for Have I Been Pwned"
  homepage "https://github.com/domfahey/pwned"
  url "https://github.com/domfahey/pwned/releases/download/v0.6.1/pwned-0.6.1.tar.gz"
  sha256 "2d355a2fcf37ae0fd5d263b45a306e96cf6350dcf8354bd66a0cfb1cbc9ac7e9"
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
