using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace TeraScanner.Helpers {
    class MemoryScanner {

        // Byte sizes
        const int BYTE = 1;
        const int CHAR = 1;
        const int INT = 4;
        const int FLOAT = 4;
        const int LONG = 4;
        const int LONGLONG = 8;

        const int ALL_ACCESS = 0x1F0FFF;

        // Process info
        const string PROCESS_NAME = "TERA";
        static public int PID = 0;
        private static Process[] GAME_PROCESS;
        private static IntPtr ProcessHandle;

        private static ThreadStart ScannerThreadRef;
        private static Thread ScannerThread;

        // Required to read memory
        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
        [DllImport("kernel32.dll")]
        public static extern bool ReadProcessMemory(int hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int64 dwSize, ref int lpNumberOfBytesRead);
        [DllImport("kernel32.dll")]
        public static extern bool CloseHandle(IntPtr hObject);

        // Compare memory
        [DllImport("msvcrt.dll")]
        public static extern int memcmp(byte[] fArray, byte[] sArray, long count);

        /* Start */
        public static void StartScanning() {
            ScannerThreadRef = new ThreadStart(Scan);
            ScannerThread = new Thread(ScannerThreadRef);
            ScannerThread.Name = "Scanner_Thread";
            ScannerThread.Start();
            Console.WriteLine($"[THREAD-LOG] Starting {ScannerThread.Name}");
        }

        private static void Scan() {
            Console.WriteLine("[LOG] Waiting TERA.exe to start...");
            while (true) {
                GAME_PROCESS = Process.GetProcessesByName(PROCESS_NAME);
                if (GAME_PROCESS.Length > 0) {
                    if (PID == 0) Console.WriteLine($"[LOG] TERA.exe detected (PID: {GAME_PROCESS[0].Id})");
                    // This means game is running
                    PID = GAME_PROCESS[0].Id;
                    try {
                        ProcessHandle = OpenProcess(ALL_ACCESS, false, PID);
                    } catch {
                        Console.WriteLine("[Error] Failed to open process, try running this as administrator.");
                    }
                    if (ProcessHandle == IntPtr.Zero) {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Missing permissions. Try running this as administrator.");
                        throw new Exception("Missing permission to read process memory");
                    }
                } else {
                    if (PID != 0) {
                        PID = 0;
                        Console.WriteLine("[LOG] TERA.exe closed by user!");
                    }
                }
                Thread.Sleep(1000);
            }
        }

        public static void StopScanning() {
            ScannerThread.Abort();
            Console.WriteLine("Stopped scanner thread");
        }

        public static void CloseProcess() {
            CloseHandle(ProcessHandle);
        }

        /* Helpers */
        public static byte[] READ_BYTES(Int64 Address, Int64 Length) {
            int bytesRead = 0;
            byte[] Buffer = new byte[Length];
            ReadProcessMemory((int)ProcessHandle, (IntPtr)Address, Buffer, Length, ref bytesRead);
            return Buffer;
        }

        public static byte READ_BYTE(Int64 Address) {
            int bytesRead = 0;
            byte[] Buffer = new byte[BYTE];
            ReadProcessMemory((int)ProcessHandle, (IntPtr)Address, Buffer, BYTE, ref bytesRead);
            return Buffer[0];
        }

        public static bool MEMCMP(byte[] fArray, byte[] sArray) {
            return memcmp(fArray, sArray, fArray.Length) == 0;
        }

    }
}
