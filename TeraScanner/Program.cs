using System;
using TeraScanner.Core;
using TeraScanner.Helpers;
using System.Runtime.InteropServices;

namespace TeraScanner {
    class Program {
        static Int64 MIN_ADDRESS = 0x0400000;
        static Int64 MAX_ADDRESS = 0x2E9A000;
        static Encryption EncryptionScanner;

        static void Main(string[] args) {
            MemoryScanner.StartScanning();
            EncryptionScanner = new Encryption(MIN_ADDRESS, MAX_ADDRESS);
            MemoryScanner.CloseProcess();
            MemoryScanner.StopScanning();
            Console.ReadLine();
        }
    }
}
