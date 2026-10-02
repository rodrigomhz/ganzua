// Ataque de texto plano conocido de Biham-Kocher contra ZipCrypto, en C++,
// expuesto como addon N-API. Es el mismo algoritmo que lib/zipcrypto-attack.js,
// portado a C++ para acelerar el bucle de búsqueda (~10-30x más rápido que JS).
//
// Algoritmo de referencia: bkcrack (autor: kimci86, licencia zlib),
// https://github.com/kimci86/bkcrack — implementación propia, no es su código.

#include <napi.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <mutex>
#include <thread>
#include <vector>

using u8 = std::uint8_t;
using u32 = std::uint32_t;

static inline u8 lsb(u32 x) { return static_cast<u8>(x); }
static inline u8 msb(u32 x) { return static_cast<u8>(x >> 24); }

// --- tablas CRC32 ----------------------------------------------------------
static u32 crctab[256];
static u32 crcinvtab[256];
static inline u32 crc32(u32 pval, u8 b) { return (pval >> 8) ^ crctab[lsb(pval) ^ b]; }
static inline u32 crc32inv(u32 crc, u8 b) { return (crc << 8) ^ crcinvtab[msb(crc)] ^ b; }
static inline u32 getYi_24_32(u32 zi, u32 zim1) { return (crc32inv(zi, 0) ^ zim1) << 24; }
static inline u32 getZim1_10_32(u32 zi_2_32) { return crc32inv(zi_2_32, 0) & 0xfffffc00u; }

// --- tablas de keystream ---------------------------------------------------
static u8 keystreamtab[1 << 14];
static std::vector<u32> keystreaminvfiltertab[256][64];
static bool keystreaminvexists[256][64];
static inline u8 getByte(u32 zi) { return keystreamtab[(zi & 0xffff) >> 2]; }
static inline const std::vector<u32>& getZiVec(u8 ki, u32 zi) {
  return keystreaminvfiltertab[ki][(zi & 0xffff) >> 10];
}
static inline bool hasZi(u8 ki, u32 zi) { return keystreaminvexists[ki][(zi & 0xffff) >> 10]; }

// --- tablas de multiplicación ----------------------------------------------
static const u32 MULT = 0x08088405u, MULTINV = 0xd94fa8cdu;
static std::vector<u8> msbprodfiber2[256], msbprodfiber3[256];

static const u32 MASK_2_32 = 0xfffffffcu, MASK_8_32 = 0xffffff00u;
static const u32 MASK_24_32 = 0xff000000u, MASK_26_32 = 0xfc000000u;
static const u32 MAXDIFF24 = 0x00ffffffu + 0xffu, MAXDIFF26 = 0x03ffffffu + 0xffu;
static const int CONTIG = 8;

static void initTables() {
  for (int b = 0; b < 256; b++) {
    u32 crc = static_cast<u32>(b);
    for (int i = 0; i < 8; i++) crc = (crc & 1) ? (crc >> 1) ^ 0xedb88320u : crc >> 1;
    crctab[b] = crc;
    crcinvtab[crc >> 24] = (crc << 8) ^ static_cast<u32>(b);
  }
  for (u32 z = 0; z < (1u << 16); z += 4) {
    u8 k = static_cast<u8>(((z | 2) * (z | 3)) >> 8);
    keystreamtab[z >> 2] = k;
    keystreaminvfiltertab[k][z >> 10].push_back(z);
    keystreaminvexists[k][z >> 10] = true;
  }
  u32 prodinv = 0;
  for (int x = 0; x < 256; x++) {
    u8 m = msb(prodinv);
    msbprodfiber2[m].push_back(static_cast<u8>(x));
    msbprodfiber2[static_cast<u8>(m + 1)].push_back(static_cast<u8>(x));
    msbprodfiber3[static_cast<u8>(m + 255)].push_back(static_cast<u8>(x));
    msbprodfiber3[m].push_back(static_cast<u8>(x));
    msbprodfiber3[static_cast<u8>(m + 1)].push_back(static_cast<u8>(x));
    prodinv += MULTINV;
  }
}

struct Keys {
  u32 x, y, z;
  Keys(u32 X, u32 Y, u32 Z) : x(X), y(Y), z(Z) {}
  inline u8 getK() const { return getByte(z); }
  inline void update(u8 p) {
    x = crc32(x, p);
    y = (y + lsb(x)) * MULT + 1;
    z = crc32(z, msb(y));
  }
  inline void updateBackward(u8 c) {
    z = crc32inv(z, msb(y));
    y = (y - 1) * MULTINV - lsb(x);
    x = crc32inv(x, static_cast<u8>(c ^ getK()));
  }
};

struct Attack {
  const std::vector<u8>& ciphertext;
  const std::vector<u8>& plaintext;
  const std::vector<u8>& keystream;
  std::size_t offset;
  std::size_t index = 0;
  u32 zlist[8], ylist[8], xlist[8];
  bool found = false;
  u32 kx = 0, ky = 0, kz = 0;

  Attack(const std::vector<u8>& c, const std::vector<u8>& p, const std::vector<u8>& k, std::size_t off)
      : ciphertext(c), plaintext(p), keystream(k), offset(off) {}

  void testXlist() {
    for (int i = 5; i <= 7; i++)
      xlist[i] = (crc32(xlist[i - 1], plaintext[index + i - 1]) & MASK_8_32) | lsb(xlist[i]);
    u32 x = xlist[7];
    for (int i = 6; i >= 3; i--) x = crc32inv(x, plaintext[index + i]);
    u32 y1_26_32 = getYi_24_32(zlist[1], zlist[0]) & MASK_26_32;
    if (static_cast<u32>(((ylist[3] - 1) * MULTINV - lsb(x) - 1) * MULTINV - y1_26_32) > MAXDIFF26) return;

    Keys kf(xlist[7], ylist[7], zlist[7]);
    kf.update(plaintext[index + 7]);
    for (std::size_t p = index + 8, c = offset + index + 8; p < plaintext.size(); ++p, ++c) {
      if (static_cast<u8>(ciphertext[c] ^ kf.getK()) != plaintext[p]) return;
      kf.update(plaintext[p]);
    }

    Keys kb(x, ylist[3], zlist[3]);
    for (std::size_t p = index + 2, c = offset + index + 2;; --p, --c) {
      kb.updateBackward(ciphertext[c]);
      if (static_cast<u8>(ciphertext[c] ^ kb.getK()) != plaintext[p]) return;
      if (p == 0) break;
    }
    for (std::size_t i = offset; i-- > 0;) kb.updateBackward(ciphertext[i]);
    found = true;
    kx = kb.x;
    ky = kb.y;
    kz = kb.z;
  }

  void exploreYlists(int i) {
    if (found) return;
    if (i != 3) {
      u32 fy = (ylist[i] - 1) * MULTINV;
      u32 ffy = (fy - 1) * MULTINV;
      for (u8 xi : msbprodfiber2[msb(ffy - (ylist[i - 2] & MASK_24_32))]) {
        u32 yim1 = fy - xi;
        if (static_cast<u32>(ffy - MULTINV * xi - (ylist[i - 2] & MASK_24_32)) <= MAXDIFF24 &&
            msb(yim1) == msb(ylist[i - 1])) {
          ylist[i - 1] = yim1;
          xlist[i] = xi;
          exploreYlists(i - 1);
          if (found) return;
        }
      }
    } else {
      testXlist();
    }
  }

  void exploreZlists(int i) {
    if (found) return;
    if (i != 0) {
      u32 zim1_10_32 = getZim1_10_32(zlist[i]);
      for (u32 zim1_2_16 : getZiVec(keystream[index + i - 1], zim1_10_32)) {
        zlist[i - 1] = zim1_10_32 | zim1_2_16;
        zlist[i] &= MASK_2_32;
        zlist[i] |= (crc32inv(zlist[i], 0) ^ zlist[i - 1]) >> 8;
        if (i < 7) ylist[i + 1] = getYi_24_32(zlist[i + 1], zlist[i]);
        exploreZlists(i - 1);
        if (found) return;
      }
    } else {
      u32 prod = (MULTINV * msb(ylist[7]) << 24) - MULTINV;
      for (u32 y7_8_24 = 0; y7_8_24 < (1u << 24); y7_8_24 += (1u << 8), prod += (MULTINV << 8)) {
        for (u8 y7_0_8 : msbprodfiber3[static_cast<u8>(msb(ylist[6]) - msb(prod))]) {
          if (static_cast<u32>(prod + MULTINV * y7_0_8 - (ylist[6] & MASK_24_32)) <= MAXDIFF24) {
            ylist[7] = y7_0_8 | y7_8_24 | (ylist[7] & MASK_24_32);
            exploreYlists(7);
            if (found) return;
          }
        }
      }
    }
  }

  void carryout(u32 z7, std::size_t idx) {
    index = idx + 1 - CONTIG;
    zlist[7] = z7;
    exploreZlists(7);
  }
};

static bool runFullAttack(const std::vector<u8>& ciphertext, const std::vector<u8>& plaintext, int offsetArg, int jobs,
                          u32& ox, u32& oy, u32& oz) {
  std::size_t offset = 12 + offsetArg;
  std::vector<u8> keystream(plaintext.size());
  for (std::size_t i = 0; i < plaintext.size(); i++) keystream[i] = plaintext[i] ^ ciphertext[offset + i];

  std::size_t index = keystream.size() - 1;
  std::vector<u32> zi;
  zi.reserve(1 << 22);
  u8 kLast = keystream[index];
  for (u32 s = 0; s < (1u << 22); s++) {
    u32 z = s << 10;
    if (hasZi(kLast, z)) zi.push_back(z);
  }

  if (keystream.size() > static_cast<std::size_t>(CONTIG)) {
    std::vector<bool> seen(1u << 22);
    bool tracking = false;
    std::vector<u32> bestCopy;
    std::size_t bestIndex = index, bestSize = 1u << 16;
    bool waiting = false;
    std::size_t wait = 0;
    for (std::size_t i = index; i >= static_cast<std::size_t>(CONTIG); i--) {
      std::fill(seen.begin(), seen.end(), false);
      std::vector<u32> next;
      std::size_t count = 0;
      u8 ki = keystream[i], kim1 = keystream[i - 1];
      for (u32 z10 : zi)
        for (u32 z216 : getZiVec(ki, z10)) {
          u32 zim1 = getZim1_10_32(z10 | z216);
          u32 bit = zim1 >> 10;
          if (!seen[bit] && hasZi(kim1, zim1)) {
            next.push_back(zim1);
            seen[bit] = true;
            count += getZiVec(kim1, zim1).size();
          }
        }
      if (count <= bestSize) {
        tracking = true;
        bestIndex = i - 1;
        bestSize = count;
        waiting = false;
      } else if (tracking) {
        if (bestIndex == i) {
          bestCopy = zi;
          if (bestSize <= (1u << 8)) {
            waiting = true;
            wait = bestSize * 4;
          }
        }
        if (waiting && --wait == 0) break;
      }
      zi.swap(next);
    }
    if (tracking) {
      if (bestIndex != static_cast<std::size_t>(CONTIG - 1)) zi.swap(bestCopy);
      index = bestIndex;
    } else {
      index = CONTIG - 1;
    }
  }

  std::vector<u32> candidates;
  u8 ki = keystream[index];
  for (u32 z : zi)
    for (u32 z2 : getZiVec(ki, z)) candidates.push_back(z | z2);

  // Reparte las candidatas entre hilos; el primero que encuentra las claves gana.
  int nThreads = jobs > 0 ? jobs : static_cast<int>(std::thread::hardware_concurrency());
  if (nThreads < 1) nThreads = 1;
  if (static_cast<std::size_t>(nThreads) > candidates.size()) nThreads = std::max<std::size_t>(1, candidates.size());

  std::atomic<bool> stop{false};
  std::atomic<std::size_t> nextIdx{0};
  std::mutex mtx;
  bool found = false;
  u32 rx = 0, ry = 0, rz = 0;

  auto worker = [&]() {
    Attack atk(ciphertext, plaintext, keystream, offset);
    for (std::size_t i = nextIdx.fetch_add(1); i < candidates.size(); i = nextIdx.fetch_add(1)) {
      if (stop.load(std::memory_order_relaxed)) return;
      atk.found = false;
      atk.carryout(candidates[i], index);
      if (atk.found) {
        std::lock_guard<std::mutex> lk(mtx);
        if (!found) {
          found = true;
          rx = atk.kx;
          ry = atk.ky;
          rz = atk.kz;
          stop.store(true);
        }
        return;
      }
    }
  };

  std::vector<std::thread> threads;
  for (int t = 0; t < nThreads; t++) threads.emplace_back(worker);
  for (auto& t : threads) t.join();

  if (found) {
    ox = rx;
    oy = ry;
    oz = rz;
    return true;
  }
  return false;
}

// --- N-API -----------------------------------------------------------------
static Napi::Value AttackWrapped(const Napi::CallbackInfo& info) {
  Napi::Env env = info.Env();
  auto cipherBuf = info[0].As<Napi::Buffer<u8>>();
  auto plainBuf = info[1].As<Napi::Buffer<u8>>();
  int offsetArg = info[2].As<Napi::Number>().Int32Value();
  int jobs = info.Length() > 3 && info[3].IsNumber() ? info[3].As<Napi::Number>().Int32Value() : 0;

  std::vector<u8> ciphertext(cipherBuf.Data(), cipherBuf.Data() + cipherBuf.Length());
  std::vector<u8> plaintext(plainBuf.Data(), plainBuf.Data() + plainBuf.Length());

  std::size_t offset = 12 + offsetArg;
  if (plaintext.size() < 12 || ciphertext.size() < offset + plaintext.size()) {
    Napi::Error::New(env, "texto plano insuficiente o offset inválido").ThrowAsJavaScriptException();
    return env.Null();
  }

  u32 x = 0, y = 0, z = 0;
  if (!runFullAttack(ciphertext, plaintext, offsetArg, jobs, x, y, z)) return env.Null();
  auto arr = Napi::Array::New(env, 3);
  arr.Set(0u, Napi::Number::New(env, static_cast<double>(x)));
  arr.Set(1u, Napi::Number::New(env, static_cast<double>(y)));
  arr.Set(2u, Napi::Number::New(env, static_cast<double>(z)));
  return arr;
}

static Napi::Object Init(Napi::Env env, Napi::Object exports) {
  initTables();
  exports.Set("attack", Napi::Function::New(env, AttackWrapped));
  return exports;
}

NODE_API_MODULE(zipcrypto_attack, Init)
