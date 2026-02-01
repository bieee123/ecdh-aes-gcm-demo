#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <optional>
#include <vector>

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

struct EVP_PKEY_CTX_Deleter
{
    void operator()(EVP_PKEY_CTX *p) const { EVP_PKEY_CTX_free(p); }
};
struct EVP_PKEY_Deleter
{
    void operator()(EVP_PKEY *p) const { EVP_PKEY_free(p); }
};
struct EVP_CIPHER_CTX_Deleter
{
    void operator()(EVP_CIPHER_CTX *p) const { EVP_CIPHER_CTX_free(p); }
};
struct EC_KEY_Deleter
{
    void operator()(EC_KEY *p) const { EC_KEY_free(p); }
};
struct EC_POINT_Deleter
{
    void operator()(EC_POINT *p) const { EC_POINT_free(p); }
};

using EVP_PKEY_CTX_ptr = std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter>;
using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>;
using EVP_CIPHER_CTX_ptr = std::unique_ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_Deleter>;
using EC_KEY_ptr = std::unique_ptr<EC_KEY, EC_KEY_Deleter>;
using EC_POINT_ptr = std::unique_ptr<EC_POINT, EC_POINT_Deleter>;

class SecureBuffer
{
public:
    SecureBuffer() : data_(nullptr), size_(0) {}

    explicit SecureBuffer(std::size_t n)
        : data_(static_cast<unsigned char *>(OPENSSL_malloc(n))), size_(n)
    {
        if (!data_)
            throw std::bad_alloc();
    }

    ~SecureBuffer()
    {
        if (data_)
        {
            OPENSSL_cleanse(data_, size_);
            OPENSSL_free(data_);
        }
    }

    SecureBuffer(SecureBuffer &&o) noexcept : data_(o.data_), size_(o.size_)
    {
        o.data_ = nullptr;
        o.size_ = 0;
    }
    SecureBuffer &operator=(SecureBuffer &&o) noexcept
    {
        if (this != &o)
        {
            if (data_)
            {
                OPENSSL_cleanse(data_, size_);
                OPENSSL_free(data_);
            }
            data_ = o.data_;
            size_ = o.size_;
            o.data_ = nullptr;
            o.size_ = 0;
        }
        return *this;
    }
    SecureBuffer(const SecureBuffer &) = delete;
    SecureBuffer &operator=(const SecureBuffer &) = delete;

    unsigned char *data() { return data_; }
    const unsigned char *data() const { return data_; }
    std::size_t size() const { return size_; }

private:
    unsigned char *data_;
    std::size_t size_;
};

static EVP_PKEY_ptr generate_ecdh_keypair()
{
    EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
    if (!ctx)
        throw std::runtime_error("EVP_PKEY_CTX_new_id failed");

    if (EVP_PKEY_keygen_init(ctx.get()) != 1)
        throw std::runtime_error("EVP_PKEY_keygen_init failed");

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(),
                                               NID_X9_62_prime256v1) != 1)
        throw std::runtime_error("curve selection failed");

    EVP_PKEY *raw = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &raw) != 1)
        throw std::runtime_error("EVP_PKEY_keygen failed");

    return EVP_PKEY_ptr(raw);
}

static std::vector<unsigned char> serialize_public_key(const EVP_PKEY_ptr &key)
{
    EC_KEY *ec_raw = EVP_PKEY_get1_EC_KEY(key.get());
    if (!ec_raw)
        throw std::runtime_error("EVP_PKEY_get1_EC_KEY failed");
    EC_KEY_ptr ec(ec_raw);

    const EC_GROUP *group = EC_KEY_get0_group(ec.get());
    const EC_POINT *point = EC_KEY_get0_public_key(ec.get());
    if (!group || !point)
        throw std::runtime_error("group/public-key extraction failed");

    size_t len = EC_POINT_point2oct(group, point,
                                    POINT_CONVERSION_UNCOMPRESSED,
                                    nullptr, 0, nullptr);
    if (len == 0)
        throw std::runtime_error("point2oct length query failed");

    std::vector<unsigned char> buf(len);
    if (EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED,
                           buf.data(), buf.size(), nullptr) == 0)
        throw std::runtime_error("point2oct encoding failed");

    return buf;
}

static EVP_PKEY_ptr deserialize_public_key(
    const std::vector<unsigned char> &data)
{

    EC_KEY *ec_raw = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec_raw)
        throw std::runtime_error("EC_KEY_new_by_curve_name failed");
    EC_KEY_ptr ec(ec_raw);

    const EC_GROUP *group = EC_KEY_get0_group(ec.get());

    EC_POINT *pt_raw = EC_POINT_new(group);
    if (!pt_raw)
        throw std::runtime_error("EC_POINT_new failed");
    EC_POINT_ptr point(pt_raw);

    if (!EC_POINT_oct2point(group, point.get(),
                            data.data(), data.size(), nullptr))
        throw std::runtime_error("deserialisation failed — point invalid or off-curve");

    if (!EC_KEY_set_public_key(ec.get(), point.get()))
        throw std::runtime_error("EC_KEY_set_public_key failed");

    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey)
        throw std::runtime_error("EVP_PKEY_new failed");

    if (EVP_PKEY_assign_EC_KEY(pkey, ec.release()) != 1)
    {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("EVP_PKEY_assign_EC_KEY failed");
    }

    return EVP_PKEY_ptr(pkey);
}

static SecureBuffer derive_shared_secret(const EVP_PKEY_ptr &private_key,
                                         const EVP_PKEY_ptr &peer_public_key)
{
    EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new(private_key.get(), nullptr));
    if (!ctx)
        throw std::runtime_error("EVP_PKEY_CTX_new failed");

    if (EVP_PKEY_derive_init(ctx.get()) != 1)
        throw std::runtime_error("derive_init failed");

    if (EVP_PKEY_derive_set_peer(ctx.get(), peer_public_key.get()) != 1)
        throw std::runtime_error("derive set_peer failed");

    size_t len = 0;
    if (EVP_PKEY_derive(ctx.get(), nullptr, &len) != 1)
        throw std::runtime_error("derive length query failed");

    SecureBuffer secret(len);
    if (EVP_PKEY_derive(ctx.get(), secret.data(), &len) != 1)
        throw std::runtime_error("EVP_PKEY_derive failed");

    return secret;
}

static SecureBuffer derive_aes_key(const SecureBuffer &shared_secret,
                                   const unsigned char *salt, size_t salt_len,
                                   const unsigned char *info, size_t info_len)
{
    constexpr size_t KEY_LEN = 32; // 256 bits

    EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr));
    if (!ctx)
        throw std::runtime_error("HKDF context creation failed");

    if (EVP_PKEY_derive_init(ctx.get()) != 1)
        throw std::runtime_error("HKDF derive_init failed");

    if (EVP_PKEY_CTX_set_hkdf_md(ctx.get(), EVP_sha256()) != 1)
        throw std::runtime_error("HKDF set_md failed");

    if (salt && salt_len > 0)
    {
        if (EVP_PKEY_CTX_set1_hkdf_salt(ctx.get(), salt,
                                        static_cast<int>(salt_len)) != 1)
            throw std::runtime_error("HKDF set1_salt failed");
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(ctx.get(), shared_secret.data(),
                                   static_cast<int>(shared_secret.size())) != 1)
        throw std::runtime_error("HKDF set1_key failed");

    if (info && info_len > 0)
    {
        if (EVP_PKEY_CTX_add1_hkdf_info(ctx.get(), info,
                                        static_cast<int>(info_len)) != 1)
            throw std::runtime_error("HKDF add_info failed");
    }

    SecureBuffer aes_key(KEY_LEN);
    size_t out_len = KEY_LEN;
    if (EVP_PKEY_derive(ctx.get(), aes_key.data(), &out_len) != 1)
        throw std::runtime_error("HKDF derive failed");

    return aes_key;
}

static std::vector<unsigned char> aes_gcm_encrypt(
    const SecureBuffer &key,
    const std::vector<unsigned char> &plaintext,
    const unsigned char *aad,
    size_t aad_len)
{

    constexpr int NONCE_LEN = 12;
    constexpr int TAG_LEN = 16;

    unsigned char nonce[NONCE_LEN];
    if (RAND_bytes(nonce, NONCE_LEN) != 1)
        throw std::runtime_error("nonce generation failed");

    EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new());
    if (!ctx)
        throw std::runtime_error("cipher context failed");

    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(),
                           nullptr, nullptr, nullptr) != 1)
        throw std::runtime_error("encrypt init (algo) failed");

    if (!EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, nullptr))
        throw std::runtime_error("set IV length failed");

    if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce) != 1)
        throw std::runtime_error("encrypt init (key+nonce) failed");

    int outl = 0;

    if (aad && aad_len > 0)
    {
        if (EVP_EncryptUpdate(ctx.get(), nullptr, &outl,
                              aad, static_cast<int>(aad_len)) != 1)
            throw std::runtime_error("AAD feed failed");
    }

    std::vector<unsigned char> ciphertext(plaintext.size());
    if (EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &outl,
                          plaintext.data(), static_cast<int>(plaintext.size())) != 1)
        throw std::runtime_error("encrypt update failed");

    if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + outl, &outl) != 1)
        throw std::runtime_error("encrypt final failed");

    unsigned char tag[TAG_LEN];
    if (!EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag))
        throw std::runtime_error("tag retrieval failed");

    std::vector<unsigned char> out;
    out.reserve(NONCE_LEN + ciphertext.size() + TAG_LEN);
    out.insert(out.end(), nonce, nonce + NONCE_LEN);
    out.insert(out.end(), ciphertext.begin(), ciphertext.end());
    out.insert(out.end(), tag, tag + TAG_LEN);
    return out;
}

static std::optional<std::vector<unsigned char>> aes_gcm_decrypt(
    const SecureBuffer &key,
    const std::vector<unsigned char> &wire,
    const unsigned char *aad,
    size_t aad_len)
{

    constexpr int NONCE_LEN = 12;
    constexpr int TAG_LEN = 16;

    if (wire.size() < static_cast<size_t>(NONCE_LEN + TAG_LEN))
        return std::nullopt;

    const unsigned char *nonce = wire.data();
    size_t ct_len = wire.size() - NONCE_LEN - TAG_LEN;
    const unsigned char *ct = wire.data() + NONCE_LEN;
    const unsigned char *tag = ct + ct_len;

    EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new());
    if (!ctx)
        return std::nullopt;

    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(),
                           nullptr, nullptr, nullptr) != 1)
        return std::nullopt;

    if (!EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, nullptr))
        return std::nullopt;

    if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce) != 1)
        return std::nullopt;

    int outl = 0;

    if (aad && aad_len > 0)
    {
        if (EVP_DecryptUpdate(ctx.get(), nullptr, &outl,
                              aad, static_cast<int>(aad_len)) != 1)
            return std::nullopt;
    }

    std::vector<unsigned char> plaintext(ct_len);
    if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &outl,
                          ct, static_cast<int>(ct_len)) != 1)
        return std::nullopt;

    if (!EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, TAG_LEN,
                             const_cast<unsigned char *>(tag)))
        return std::nullopt;

    if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + outl, &outl) != 1)
        return std::nullopt; // tag mismatch — discard everything

    return plaintext;
}

int main()
{
    try
    {
        std::cout << "[1/4] Generating ECDH key pairs (P-256)..." << std::endl;
        EVP_PKEY_ptr Moniq_key = generate_ecdh_keypair();
        EVP_PKEY_ptr Resya_key = generate_ecdh_keypair();

        std::cout << "[2/4] Exchanging public keys..." << std::endl;
        auto Moniq_pub_bytes = serialize_public_key(Moniq_key);
        auto Resya_pub_bytes = serialize_public_key(Resya_key);

        EVP_PKEY_ptr Moniq_pub_remote = deserialize_public_key(Moniq_pub_bytes);
        EVP_PKEY_ptr Resya_pub_remote = deserialize_public_key(Resya_pub_bytes);

        std::cout << "   Moniq public key: " << Moniq_pub_bytes.size() << " bytes\n";
        std::cout << "   Resya   public key: " << Resya_pub_bytes.size() << " bytes\n";

        std::cout << "[3/4] Deriving shared secret and AES key..." << std::endl;

        SecureBuffer Moniq_shared = derive_shared_secret(Moniq_key, Resya_pub_remote);
        SecureBuffer Resya_shared = derive_shared_secret(Resya_key, Moniq_pub_remote);

        if (Moniq_shared.size() != Resya_shared.size() ||
            memcmp(Moniq_shared.data(), Resya_shared.data(), Moniq_shared.size()) != 0)
            throw std::runtime_error("shared secrets do not match");

        std::cout << "   Shared secret: " << Moniq_shared.size() << " bytes\n";

        const char *salt = "ecdh-demo-salt-v1";
        const char *info = "ecdh-demo:aes256gcm:session1";

        SecureBuffer Moniq_aes = derive_aes_key(
            Moniq_shared,
            reinterpret_cast<const unsigned char *>(salt), strlen(salt),
            reinterpret_cast<const unsigned char *>(info), strlen(info));

        SecureBuffer Resya_aes = derive_aes_key(
            Resya_shared,
            reinterpret_cast<const unsigned char *>(salt), strlen(salt),
            reinterpret_cast<const unsigned char *>(info), strlen(info));

        if (Moniq_aes.size() != Resya_aes.size() ||
            memcmp(Moniq_aes.data(), Resya_aes.data(), Moniq_aes.size()) != 0)
            throw std::runtime_error("derived AES keys do not match");

        std::cout << "   AES-256 key:    " << Moniq_aes.size() << " bytes\n";

        std::cout << "[4/4] Encrypting and decrypting message..." << std::endl;

        const std::string msg = "Hello Resya, this channel is secure.";
        std::vector<unsigned char> pt(msg.begin(), msg.end());

        const char *aad = "recipient=Resya;sender=Moniq";

        auto wire = aes_gcm_encrypt(
            Moniq_aes, pt,
            reinterpret_cast<const unsigned char *>(aad), strlen(aad));

        std::cout << "   Encrypted payload: " << wire.size()
                  << " bytes (nonce + ciphertext + tag)\n";

        auto result = aes_gcm_decrypt(
            Resya_aes, wire,
            reinterpret_cast<const unsigned char *>(aad), strlen(aad));

        if (!result)
            throw std::runtime_error("decryption or authentication failed");

        std::string decrypted(result->begin(), result->end());
        std::cout << "   Decrypted message : \"" << decrypted << "\"\n";

        if (decrypted != msg)
            throw std::runtime_error("plaintext mismatch after round-trip");

        std::cout << "\n[OK] ECDH + AES-GCM completed successfully.\n";
    }
    catch (const std::exception &e)
    {
        std::cerr << "[FATAL] " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
