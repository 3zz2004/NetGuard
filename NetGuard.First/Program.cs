using System;
using System.Net.NetworkInformation;
using System.Diagnostics;
using System.Net.Sockets;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;

namespace NetGuard.First
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("=== Welcome to NetGuard ===");
            Console.ResetColor();

            while (true)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("\nWhat do you want?");
                Console.WriteLine("1 >> Ping Request");
                Console.WriteLine("2 >> Find MAC address");
                Console.WriteLine("3 >> Port Scanning");
                Console.WriteLine("4 >> Network Card Info");
                Console.ResetColor();

                Console.ForegroundColor = ConsoleColor.Blue;
                Console.Write("Enter your choice: ");
                Console.ResetColor();

                string Purpose = Console.ReadLine();
                int ParsedPurpose = int.Parse(Purpose);

                if (ParsedPurpose == 1)
                {
                    Console.ForegroundColor = ConsoleColor.Blue;
                    Console.Write("Enter the Host Name: ");
                    Console.ResetColor();

                    string host = Console.ReadLine();
                    Ping pingsender = new Ping();

                    try
                    {
                        PingReply reply = pingsender.Send(host, 3000);
                        if (reply.Status == IPStatus.Success)
                        {
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine($"Success - Reply from {reply.Address} - Time={reply.RoundtripTime}ms");
                        }
                        else
                        {
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine("Failed to reach host");
                        }
                        Console.ResetColor();
                    }
                    catch (Exception ex)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Error: " + ex.Message);
                        Console.ResetColor();
                    }
                }
                else if (ParsedPurpose == 2)
                {
                    Process P = new Process();
                    P.StartInfo.FileName = "arp";
                    P.StartInfo.Arguments = "-a";
                    P.StartInfo.UseShellExecute = false;
                    P.StartInfo.RedirectStandardOutput = true;
                    P.StartInfo.CreateNoWindow = true;

                    P.Start();
                    string Output = P.StandardOutput.ReadToEnd();
                    P.WaitForExit();

                    Console.ForegroundColor = ConsoleColor.White;
                    Console.WriteLine(Output);
                    Console.ResetColor();
                }
                else if (ParsedPurpose == 3)
                {
                    Console.Write("Enter the IP Address: ");
                    string ip = Console.ReadLine();
                    Console.Write("Enter the Start port: ");
                    int start = int.Parse(Console.ReadLine());
                    Console.Write("Enter the End port: ");
                    int end = int.Parse(Console.ReadLine());

                    Console.WriteLine($"\nI will scan for you from {start} to {end} now...");

                    int timeout = 300;
                    var tasks = new List<Task>();
                    var results = new List<string>();
                    var openPorts = new List<int>();

                    string header = $"=== Port Scan Results ({DateTime.Now}) ===";
                    results.Add(header);

                    for (int port = start; port <= end; port++)
                    {
                        int p = port;
                        tasks.Add(Task.Run(async () =>
                        {
                            using (TcpClient tcp_client = new TcpClient())
                            {
                                try
                                {
                                    var connectTask = tcp_client.ConnectAsync(ip, p);
                                    if (await Task.WhenAny(connectTask, Task.Delay(timeout)) == connectTask)
                                    {
                                        string banner = GrabBanner(ip, p);
                                        string result = $"(Open) : {p} {banner}";
                                        Console.ForegroundColor = ConsoleColor.Green;
                                        Console.WriteLine(result);
                                        results.Add(result);
                                        openPorts.Add(p);
                                    }
                                    else
                                    {
                                        string result = $"(Closed/Timeout) : {p}";
                                        Console.ForegroundColor = ConsoleColor.Red;
                                        Console.WriteLine(result);
                                        results.Add(result);
                                    }
                                }
                                catch
                                {
                                    string result = $"(Closed) : {p}";
                                    Console.ForegroundColor = ConsoleColor.Red;
                                    Console.WriteLine(result);
                                    results.Add(result);
                                }
                                finally
                                {
                                    Console.ResetColor();
                                }
                            }
                        }));
                    }

                    Task.WaitAll(tasks.ToArray());

                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine("\n=== Security Report ===");
                    Console.ResetColor();

                    Console.WriteLine($"Open Ports: {openPorts.Count}");
                    var riskyPorts = new Dictionary<int, string>
                    {
                        {21, "FTP"},
                        {23, "Telnet"},
                        {25, "SMTP"},
                        {135, "RPC"},
                        {139, "NetBIOS"},
                        {445, "SMB"},
                        {3389, "RDP"}
                    };

                    var foundRisks = new List<string>();
                    foreach (var rp in riskyPorts)
                    {
                        if (openPorts.Contains(rp.Key))
                            foundRisks.Add($"{rp.Key} ({rp.Value})");
                    }

                    if (foundRisks.Count > 0)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Critical Ports: " + string.Join(", ", foundRisks));
                        Console.ResetColor();

                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine("Recommendation: Close unnecessary ports, replace insecure services (e.g., use SSH instead of Telnet).");
                        Console.ResetColor();
                    }
                    else
                    {
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine("No critical risky ports detected.");
                        Console.ResetColor();
                    }

                    File.AppendAllLines("PortScanResults.txt", results);
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine($"\n[+] Results saved in PortScanResults.txt");
                    Console.ResetColor();
                }
                else if (ParsedPurpose == 4)
                {
                    foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
                    {
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine($"\nName: {nic.Name}");
                        Console.ResetColor();

                        Console.WriteLine($"Description: {nic.Description}");
                        Console.WriteLine($"Status: {nic.OperationalStatus}");
                        Console.WriteLine($"MAC Address: {nic.GetPhysicalAddress()}");

                        var ipProps = nic.GetIPProperties();
                        foreach (var ip in ipProps.UnicastAddresses)
                        {
                            Console.WriteLine($"IP Address: {ip.Address}");
                        }
                        Console.WriteLine("--------------------------");
                    }
                }

                Console.ForegroundColor = ConsoleColor.Blue;
                Console.WriteLine("\nDo you want to do another thing?? (yes , no)");
                Console.ResetColor();

                string answer = Console.ReadLine();
                if (answer.ToLower() == "no")
                {
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    Console.WriteLine("Thanks for using NetGuard , see you next time!");
                    Console.ResetColor();
                    break;
                }
                else if (answer.ToLower() == "yes")
                {
                    continue;
                }
            }
        }

        static string GrabBanner(string ip, int port)
        {
            try
            {
                using (TcpClient client = new TcpClient(ip, port))
                using (NetworkStream stream = client.GetStream())
                {
                    stream.ReadTimeout = 500;
                    if (port == 80 || port == 443)
                    {
                        byte[] data = System.Text.Encoding.ASCII.GetBytes("HEAD / HTTP/1.0\r\n\r\n");
                        stream.Write(data, 0, data.Length);
                    }

                    byte[] buffer = new byte[256];
                    int bytes = stream.Read(buffer, 0, buffer.Length);
                    if (bytes > 0)
                    {
                        string response = System.Text.Encoding.ASCII.GetString(buffer, 0, bytes);
                        string firstLine = response.Split('\n')[0].Trim();
                        return $"-> Banner: {firstLine}";
                    }
                }
            }
            catch { }
            return "-> No banner";
        }
    }
}
