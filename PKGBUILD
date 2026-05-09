# Maintainer: local
pkgname=dnsbench
pkgver=0.1.0
pkgrel=1
pkgdesc='Qt6 desktop tool for benchmarking DNS resolvers'
arch=('x86_64')
license=('MIT')
depends=('gcc-libs' 'glibc' 'openssl' 'qt6-base' 'qt6-charts')
makedepends=('cmake' 'ninja' 'nlohmann-json')
options=('!debug')
source=()

build() {
  cmake -S "$startdir" -B "$startdir/build/makepkg" -G Ninja \
    -DCMAKE_BUILD_TYPE=None \
    -DCMAKE_INSTALL_PREFIX=/usr \
    -DCMAKE_SKIP_RPATH=ON
  cmake --build "$startdir/build/makepkg"
}

check() {
  ctest --test-dir "$startdir/build/makepkg" --output-on-failure
}

package() {
  DESTDIR="$pkgdir" cmake --install "$startdir/build/makepkg"
}
