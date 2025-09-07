class CrestronDiscover < Formula
  desc "Short description of your tool"
  homepage "https://github.com/mikejobson/crestron-discover"
  url "https://github.com/mikejobson/crestron-discover/releases/download/v0.1.0/crestron-discover"
  sha256 "2c5b39f11f688988eea4d2e3fce89235a2728f8df6998a1b220ec697ca08de42"
  version "0.1.0"
  license "MIT" # or your license

  def install
    bin.install "crestron-discover"
  end

  test do
    system "#{bin}/crestron-discover", "--help"
  end
end