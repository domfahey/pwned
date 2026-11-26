class HomebrewFormulaPwnedTest < Formula
  include Language::Python::Virtualenv

  desc "Command-line interface and Python client for Have I Been Pwned"
  homepage "https://github.com/domfahey/pwned"
  url "https://files.pythonhosted.org/packages/source/p/pwned/pwned-0.2.0.tar.gz"
  sha256 "PLACEHOLDER_SHA256"
  license "MIT"

  depends_on "python@3.12"

  def install
    virtualenv_install_with_resources
  ] if respond_to?(:virtualenv_install_with_resources)
    virtualenv_install_with_resources
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/pwned --version")
  end
end
# NOTE: Copy this file into your `homebrew-tap` repository (e.g. `Formula/pwned.rb`),
# and fill in the exact `url`, `sha256`, and any required `resource` blocks generated
# via `homebrew-pypi-poet`.
