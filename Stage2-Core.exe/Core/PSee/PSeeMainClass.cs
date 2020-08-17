using PSeeLibrary;
using System;
using System.Text;

namespace PSee
{
    public class PSeeMainClass
    {
        public static void Run()
        {
            try
            {
                Console.WriteLine($"#################");
                Console.WriteLine($"MachineEnum");
                Console.WriteLine($"#################");
                try
                {
                    MachineEnum();
                } catch (Exception e){
                    Console.WriteLine(e);
                }
                Console.WriteLine($"#################");
                Console.WriteLine($"UserEnum");
                Console.WriteLine($"#################");                
                try
                {
                    UserEnum();
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                }
                Console.WriteLine($"#################");
                Console.WriteLine($"RecentFiles");
                Console.WriteLine($"#################");                
                try
                {
                    RecentFiles(50);
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                }
                Console.WriteLine($"####################");
                Console.WriteLine($"Suspicious Processes");
                Console.WriteLine($"####################");
                try
                {
                    Processes();
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                }
                Console.WriteLine($"#################");
                Console.WriteLine($"ChromeBook");
                Console.WriteLine($"#################");                
                try
                {
                    ChromeBook();
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                }
                Console.WriteLine($"#################");
                Console.WriteLine($"IEBook");
                Console.WriteLine($"#################");                
                try
                {
                    IEBook();
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                }
                Console.WriteLine($"#################");
                Console.WriteLine($"EnumSoftware");
                Console.WriteLine($"#################");                
                try
                {
                    EnumSoftware();
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                }
            }
            catch (Exception ex) { Console.WriteLine(ex.Message); }
        }

        public static void MachineEnum()
        {
            var sb = new StringBuilder();
            foreach (var n in PSeeMain.MachineEnum())
            {
                sb.Append("\t");
                sb.Append(n.Key);
                sb.Append(":");
                sb.AppendLine(n.Value);
            }
            Console.WriteLine(sb.ToString());
        }

        public static void UserEnum()
        {
            var sb = new StringBuilder();
            foreach (var n in PSeeMain.UserEnum())
            {
                sb.Append("\t");
                sb.Append(n.Key);
                sb.Append(": ");
                sb.AppendLine(n.Value);
            }
            Console.WriteLine(sb.ToString());
        }

        public static void RecentFiles(Int32 FileCount = 10)
        {
            var sb = new StringBuilder();
            foreach (var n in PSeeMain.RecentFiles(FileCount)) sb.AppendLine("\t" + n);

            Console.WriteLine(sb.ToString());
        }

        public static void Processes()
        {
            var sb = new StringBuilder();
            foreach (var n in PSeeMain.EnumProcesses()) sb.AppendLine("\t" + n);
            Console.WriteLine(sb.ToString());
        }

        public static void ChromeBook()
        {
            var sb = new StringBuilder();
            foreach (var n in PSeeMain.ChrBookmarks()) sb.AppendLine("\t" + n);
            Console.WriteLine(sb.ToString());
        }

        public static void IEBook()
        {
            var sb = new StringBuilder();
            foreach (var n in PSeeMain.IEBookmarks()) sb.AppendLine("\t" + n);
            Console.WriteLine(sb.ToString());
        }

        public static void EnumSoftware()
        {
            var sb = new StringBuilder();
            foreach (var n in PSeeMain.InstSoftware()) sb.AppendLine("\t" + n);
            Console.WriteLine(sb.ToString());
        }

        public static void UsersForGroup(string Groups)
        {
            var sb = new StringBuilder();
            if (String.IsNullOrEmpty(Groups))
            {
                Console.WriteLine("Group name is empty");
                return;
            }
            else
            {
                foreach (var n in PSeeMain.GetUsersForGroup(Groups)) sb.AppendLine("\t" + n);
                Console.WriteLine(sb.ToString());
            }
        }
    }
}
