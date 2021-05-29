#ifndef AES_ENGINE_H
#define AES_ENGINE_H

#include <vector>


typedef std::vector<unsigned char> ByteArray;

#define bs 16

class AES_Engine {

    public:
        AES_Engine(const ByteArray& key);
        ~AES_Engine();

        // Метод начинает кодирование
        static ByteArray::size_type encrypt(const ByteArray& key,
                                            const ByteArray& plain,
                                            ByteArray& encrypted);
        // Метод начинает декодирование
        static ByteArray::size_type decrypt(const ByteArray& key,
                                            const ByteArray& encrypted,
                                            ByteArray& plain);

        // Первая стадия кодирования
        ByteArray::size_type encryptStart(const ByteArray::size_type plain_length,
                                           ByteArray& encrypted);
        // Вторая стадия кодирования
        ByteArray::size_type encryptContinue(const ByteArray& plain,
                                              ByteArray& encrypted);
        // Третья стадия кодирования
        ByteArray::size_type encryptEnd(ByteArray& encrypted);

        // Первая стадия декодирования
        ByteArray::size_type decryptStart(const ByteArray::size_type encrypted_length);
        // Вторая стадия декодирования
        ByteArray::size_type decryptContinue(const ByteArray& encrypted, ByteArray& plain);
        // Третья стадия декодирования
        ByteArray::size_type decryptEnd(ByteArray& plain);

    private:
        ByteArray mKey;
        ByteArray mSalt;
        ByteArray mRkey;

        unsigned char mBuffer[3 * bs];
        unsigned char mBufferPos;
        ByteArray::size_type mRemainingLength;

        bool mDecryptInitialized;

        void checkAndEncryptBuffer(ByteArray& encrypted);
        void checkAndDecryptBuffer(ByteArray& plain);

        void encrypt(unsigned char *buffer);
        void decrypt(unsigned char *buffer);

        // Процедуры генерации раундовых ключей
        void expandEncKey(unsigned char *rc);
        void expandDecKey(unsigned char *rc);

        // Процедуры трансформации при шифровании (расшифровании),
        // которые обрабатывают state(buffer) таким образом,
        // что применяет таблицу замещения байтов из sbox
        // независимо к каждому байту state(buffer)
        void subBytes(unsigned char *buffer);
        void subBytesInv(unsigned char *buffer);

        void copyKey();

        // Трансформация при шифровании и обратном шифровании,
        // при которой используется XOR между State (buffer) и Round Key (round)
        void addRoundKey(unsigned char *buffer, const unsigned char round);

        // Трансформации при шифровании (расшифровании), которые обрабатывают State, циклически
        // смещая последние три строки State на разные величины
        void shiftRows(unsigned char *buffer);
        void shiftRowsInv(unsigned char *buffer);

        // Трансформация при шифровании (расшифровании), которая берёт все столбцы State и смешивает их данные (независимо друг от друга),
        // чтобы получить новые столбцы
        void mixColumns(unsigned char *buffer);
        void mixColumnsInv(unsigned char *buffer);
};

#endif // AES_ENGINE_H
