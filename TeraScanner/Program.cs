using System;
using TeraScanner.Core;
using TeraScanner.Helpers;

namespace TeraScanner {
    class Program {
        static Int64 MIN_ADDRESS = 0x0400000;
        static Int64 MAX_ADDRESS = 0x2E75000;
        static Encryption EncryptionScanner;

        static void Main(string[] args) {
            MemoryScanner.StartScanning();
            EncryptionScanner = new Encryption(MIN_ADDRESS, MAX_ADDRESS);
            MemoryScanner.CloseProcess();
            MemoryScanner.StopScanning();
        }
    }
}
