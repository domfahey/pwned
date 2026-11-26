class Pwned < Formula
  include Language::Python::Virtualenv

  desc "Command-line interface and Python client for Have I Been Pwned"
  homepage "https://github.com/domfahey/pwned"
  url "https://github.com/domfahey/pwned/releases/download/v0.3.0/pwned-0.3.0.tar.gz"
  sha256 "9768e8db91b93d6dab7306d9c9e91c0552e75863999e40c4165d7a41a99d2762"
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
