using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using Core.Common;

namespace Core
{
    public class Program
    {
        public static Dictionary<string, string> arguments = new Dictionary<string, string>();

        public static void PrintHelp()
        {
            Console.WriteLine("");
            Console.WriteLine("PoshC2 - Core Module");
            Console.WriteLine("===========================================");

            MethodInfo[] methodInfo = typeof(Core).GetMethods();
            try
            {
                foreach (MethodInfo temp in methodInfo)
                {
                    var method = typeof(Core).GetMethod(temp.Name);
                    object[] atts = method.GetCustomAttributes(true);
                    if (atts.Length > 0)
                    {
                        Console.WriteLine((atts[0] as CoreDispatch).Usage.ToString());
                    }
                }
            }
            catch (NullReferenceException) { }
            catch (Exception e) { Console.WriteLine($"Error in help: {e}"); }

        }
        public static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                PrintHelp();
                return;
            }
            try
            {
                Run(args);
            }
            catch (Exception e)
            {
                Console.WriteLine("Core generated an error: '{0}'", e);
            }
        }
        static void Run(string[] args)
        {
            var methodName = args[0].ToLower();
            methodName = methodName.Replace("-", "");
            var cliArgs = args;

            // parse args like in SharpWMI - https://github.com/GhostPack/SharpWMI/blob/master/SharpWMI/Program.cs
            foreach (string argument in args)
            {
                int idx = argument.IndexOf('=');
                if (idx > 0)
                    arguments[argument.Substring(0, idx)] = argument.Substring(idx + 1);
            }

            MethodInfo[] methodInfo = typeof(Core).GetMethods();
            try
            {
                foreach (MethodInfo temp in methodInfo)
                {
                    if (methodName == temp.Name)
                    {
                        goto runmethod;
                    } 
                }
                Console.WriteLine("[!] No command found in core");
                goto end;
            }
            catch (NullReferenceException e) { Console.WriteLine($"NullReferenceException Error in help: {e}"); }
            catch (Exception e) { Console.WriteLine($"Error in help: {e}"); }

            runmethod:
            var method = typeof(Core).GetMethod(methodName);
            var prop = typeof(Core).GetProperties();
            if (method == null)
            {
                Console.WriteLine($@"There is no method does match with '{methodName}'");
                return;
            }
            if (args.Length > 1 && (args[1].ToLower() == "-help" || args[1].ToLower() == "help" || args[1].ToLower() == "?" || args[1].ToLower() == "-h"))
            {
                object[] atts = method.GetCustomAttributes(true);
                if (atts.Length > 0)
                {
                    Console.WriteLine((atts[0] as CoreDispatch).Description.ToString());
                    Console.WriteLine();
                    Console.WriteLine((atts[0] as CoreDispatch).Usage.ToString());
                }                    
                goto end;
            }
            ParameterInfo[] parameters = method.GetParameters();
            if (parameters == null || parameters.Length != 1)
            {
                // The method has no parameter
                method.Invoke(null, null);
                return;
            }
            else if(cliArgs.Length < 2 && parameters.Length > 0)
            {
                // If no params are passed when they are expecting some
                Console.WriteLine("No parameters passed");
                return;
            }
            else
            {                
                method.Invoke(null, new object[] { cliArgs });
            }

            end:
            Console.Write("");
        }
    }
}
