class Pwned < Formula
  include Language::Python::Virtualenv

  desc "Command-line interface and Python client for Have I Been Pwned"
  homepage "https://github.com/domfahey/pwned"
  url "https://github.com/domfahey/pwned/releases/download/v0.2.0/pwned-0.2.0.tar.gz"
  sha256 "16093beb6bc94a38e8fc93cd334b0f48a6026b2486a5ffdb403467f4262932d0"
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
