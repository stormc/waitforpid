pkgname=waitforpid-git
pkgver=1.0
pkgrel=1
pkgdesc="Wait for a (non-child) process' exit using Linux's CONFIG_PROC_EVENTS"
arch=('i686' 'x86_64')
url="https://github.com/stormc/waitforpid"
license=('GPL')
depends=('libcap')
makedepends=('git')
source=("$pkgname"::'git+https://github.com/stormc/waitforpid.git')
md5sums=('SKIP')
install=waitforpid.install

build() {
  cd "$srcdir/$pkgname"
  make
}

package() {
  cd "$srcdir/$pkgname"
  make PREFIX=/usr DESTDIR="$pkgdir" install
}
