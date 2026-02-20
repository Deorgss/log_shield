#!/usr/bin/perl
use strict;
use warnings;

# Настройки
# Принимаем путь к логу из первого аргумента командной строки
# Если аргумент не передан, используем 'access.log' по умолчанию
my $log_file = $ARGV[0] // '/var/log/nginx/access.log';
# Лимит запросов, после которого IP считается подозрительным
my $threshold = $ARGV[1] * 1000 // 100000;
my %ip_stats;
my $fh;

print "--- LogShield: Analysis Started with threshold #$threshold ---\n";

# Открываем файл лога
if (!open($fh, '<', $log_file)) {
    die "Could not open log file: $!";
}

while (my $line = <$fh>) {
    # Регулярное выражение для извлечения IP из стандартного лога Nginx/Apache
    if ($line =~ /^(\d+\.\d+\.\d+\.\d+)\s/) {
        my $ip = $1;
        $ip_stats{$ip}++;
    }
}
close($fh);

# Выводим отчет о подозрительной активности
print "Suspicious Activity Report:\n";
print "-----------------------------------\n";
printf("%-15s | %-10s\n", "IP Address", "Requests");
print "-----------------------------------\n";

my $found_threats = 0;
foreach my $ip (sort { $ip_stats{$b} <=> $ip_stats{$a} } keys %ip_stats) {
    if ($ip_stats{$ip} > $threshold) {
        printf("%-15s | %-10d (POTENTIAL ATTACK)\n", $ip, $ip_stats{$ip});
        $found_threats++;
    }
}

if ($found_threats == 0) {
    print "No suspicious activity detected based on current threshold.\n";
}

print "-----------------------------------\n";
print "Analysis Complete.\n";
