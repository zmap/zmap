require 'formula'

class Zmap < Formula
  homepage 'https://zmap.io'
  url 'https://github.com/zmap/zmap/archive/v1.1.1.1.tar.gz'
  sha1 '0c53e6e6cfe35aefd7b018e41b80674fa25c3d49'

  depends_on 'cmake' => :build
  depends_on 'gengetopt' => :build
  depends_on 'byacc' => :build
  depends_on 'libdnet'
  depends_on 'gmp'
  depends_on 'json-c'

  def install
    system "cmake", "-DWITH_JSON=ON", "-DRESPECT_INSTALL_PREFIX_CONFIG=ON", ".", *std_cmake_args
    system "make", "install"
  end

  test do
    system "#{bin}/zmap", "--version"
  end
end
