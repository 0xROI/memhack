#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void execute_command(const char *command) {
    int result = system(command);
    if (result == -1) {
        perror("Error executing command");
        exit(EXIT_FAILURE);
    }
}

void generate_filename(char *buffer, const char *scan_type, const char *target_ip) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char time_str[100];
    strftime(time_str, sizeof(time_str), "%Y%m%d_%H%M%S", t);
    sprintf(buffer, "nmap_%s_scan_%s_%s.txt", scan_type, target_ip, time_str);
}

void perform_scan(const char *target_ip, const char *scan_type) {
    char command[512];
    char output_file[100];
    char open_ports[256] = "";
    FILE *fp;

    generate_filename(output_file, scan_type, target_ip);

    // Perform the initial scan and save the output
    if (strcmp(scan_type, "tcp") == 0) {
        sprintf(command, "nmap -p- --min-rate=1000 -T4 %s -oN %s", target_ip, output_file);
    } else {
        sprintf(command, "nmap -sU -p 1-65535 --min-rate=1000 -T4 %s -oN %s", target_ip, output_file);
    }
    printf("Running initial %s scan on %s...\n", scan_type, target_ip);
    execute_command(command);

    // Extract open ports from the output file
    sprintf(command, "grep 'open' %s | awk '{print $1}' | cut -d'/' -f1 | tr '\\n' ',' | sed 's/,$//' > open_ports.txt", output_file);
    execute_command(command);

    // Read open ports from the temporary file
    fp = fopen("open_ports.txt", "r");
    if (fp == NULL) {
        perror("Error reading open ports");
        exit(EXIT_FAILURE);
    }
    if (fgets(open_ports, sizeof(open_ports), fp) != NULL) {
        printf("Open ports found: %s\n", open_ports);
    }
    fclose(fp);
    remove("open_ports.txt");

    // Run an aggressive scan on the open ports
    if (strlen(open_ports) > 0) {
        if (strcmp(scan_type, "tcp") == 0) {
            sprintf(command, "nmap -A -p%s %s -oN %s", open_ports, target_ip, output_file);
        } else {
            sprintf(command, "nmap -A -sU -p%s %s -oN %s", open_ports, target_ip, output_file);
        }
        printf("Running aggressive %s scan on %s on ports: %s...\n", scan_type, target_ip, open_ports);
        execute_command(command);
    } else {
        printf("No open ports found. Results saved in %s.\n", output_file);
    }

    printf("Aggressive %s scan completed on %s. Results saved in %s.\n", scan_type, target_ip, output_file);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <target-ip> [tcp|udp]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *target_ip = argv[1];
    const char *scan_type = (argc > 2) ? argv[2] : "tcp";

    if (strcmp(scan_type, "tcp") != 0 && strcmp(scan_type, "udp") != 0) {
        printf("Invalid scan type: %s. Choose 'tcp' or 'udp'.\n", scan_type);
        exit(EXIT_FAILURE);
    }

    perform_scan(target_ip, scan_type);
    return 0;
}