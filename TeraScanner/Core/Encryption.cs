using System;
using System.Threading;
using TeraScanner.Helpers;

namespace TeraScanner.Core {
    class Encryption {

        ThreadStart EncryptionThreadRef;
        Thread EncryptionThread;

        private DateTime Start;
        private DateTime Finish;

        // Address range to scan for signature
        private Int64 BaseAddress;
        private Int64 MaxAddress;
        private Int64 EncryptionAddress;

        // Encryption key and IV;
        private string KEY;
        private string IV;

        /* This will find the KEY and IV for TERA's encryption */
        private byte[] SIGNATURE = new byte[] {
            0x56,                                   // push esi
            0x57,                                   // push edi
            0x50,                                   // push eax
            0x8D, 0x45, 0xF4,                       // lea eax,[ebp-0C]
            0x64, 0xA3, 0x00, 0x00, 0x00, 0x00,     // mov fs:[00000000],eax
            0x8B, 0x73, 0x08,                       // mov esi,[ebx+08]
            0x8B, 0xCE                              // mov ecx, esi
        };

        public Encryption(Int64 FromAddress, Int64 ToAddress) {
            BaseAddress = FromAddress;
            MaxAddress = ToAddress;
            // Threading for later
            //EncryptionThreadRef = new ThreadStart(ScanPattern);
            //EncryptionThread = new Thread(EncryptionThreadRef);
            //EncryptionThread.Name = "Encryption_Thread";
            //EncryptionThread.Start();
            ScanPattern();
        }

        private void ScanPattern() {
            if (MemoryScanner.PID != 0) {
                Console.WriteLine("Started Encryption scanner");
                ScanMemoryForSignature();
                GetKEY();
                GetIV();
                Console.WriteLine($"\nTime taken: {(Finish - Start).ToString()}");
            } else {
                Thread.Sleep(1000);
                ScanPattern(); // Recursion poggers
            }
        }

        private void ScanMemoryForSignature() {
            Start = DateTime.UtcNow;
            byte[] data = MemoryScanner.READ_BYTES(BaseAddress, MaxAddress-BaseAddress);
            byte[] cmpArray = new byte[SIGNATURE.Length];
            for (int BYTE = 0; BYTE < data.Length; BYTE++) {
                if (data[BYTE] != SIGNATURE[0]) continue;
                Buffer.BlockCopy(data, BYTE, cmpArray, 0, SIGNATURE.Length);
                if (MemoryScanner.MEMCMP(cmpArray, SIGNATURE)) {
                    Finish = DateTime.UtcNow;
                    EncryptionAddress = BaseAddress + BYTE + SIGNATURE.Length;
                    //Console.WriteLine($"{EncryptionAddress:X}");
                    return;
                }
            }
            Finish = DateTime.UtcNow;
            Console.WriteLine("Signature for encryption not found.");
            // Clear byte arrays
            data = null;
            cmpArray = null;
        }

        private void GetKEY() {
            int offset = 0;
            for (int keyPart = 0; keyPart < 4; keyPart++) {
                byte[] value = MemoryScanner.READ_BYTES(EncryptionAddress + (keyPart * 7 + offset), 7);
                // C7 45 ?? ?? ?? ?? ??         mov [ebp-??],????????
                if (value[0] == 0xC7 && value[1] == 0x45) {
                    for (int byteIndex = 3; byteIndex < value.Length; byteIndex++) {
                        KEY = $"{KEY}{value[byteIndex]:X}";
                    }
                } else if (value[0] == 0x8B && value[1] == 0x06) {
                    // 8B 06                    mov eax,[esi]
                    keyPart--;
                    offset = 2;
                    continue;
                }
            }
            Console.Write("KEY: ");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(KEY);
            Console.ForegroundColor = ConsoleColor.White;
        }
        
        private void GetIV() {
            int offset = 0;
            for (int IVPart = 0; IVPart < 4; IVPart++) {
                byte[] value = MemoryScanner.READ_BYTES(EncryptionAddress + 0x1E + (IVPart * 7 + offset), 7);
                // C7 45 ?? ?? ?? ?? ??         mov [ebp-??],????????
                if (value[0] == 0xC7 && value[1] == 0x45) {
                    for (int byteIndex = 3; byteIndex < value.Length; byteIndex++) {
                        IV = $"{IV}{value[byteIndex]:X}";
                    }
                } else if (value[0] == 0x8B && value[1] == 0x40) {
                    IVPart--;
                    offset = 3;
                    continue;
                }
            }
            Console.Write("IV:  ");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(IV);
            Console.ForegroundColor = ConsoleColor.White;
        }

    }
}
