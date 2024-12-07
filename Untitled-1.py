
import re  # Regular expresions for the log file
import csv  #enables save in csv file
from collections import Counter #counts occurence of items

log_file_ = r"C:\Users\jaikanth\Documents\python scprit\sample.txt" #loc of log file 

output_file_ = "log_analysis_results.csv" #output csv file

failedLogin_threshold = 10 #no of failed login attempt

 
def analyze_log(log_file_):
    ip_Requests = Counter()
    endpoint_Requests = Counter()
    failed_Logins = Counter()
    
    log_pattern = r'(\d+\.\d+\.\d+\.\d+).*?"(GET|POST) (\/\S*) HTTP.*?" (\d+)'
    failed_login_pattern = r'401|Invalid credentials'
    
    with open(log_file_, 'r') as file:
        for line in file:
            match = re.search(log_pattern, line)
            if match:
                ip = match.group(1)
                endpoint = match.group(3)
                status_code = match.group(4)

                # Count requests per IP and endpoint
                ip_Requests[ip] += 1
                endpoint_Requests[endpoint] += 1

                # Check for failed login attempts
                if re.search(failed_login_pattern, line):
                    failed_Logins[ip] += 1

    # Identify the most accessed endpoint
    most_accessed_endpoint = endpoint_Requests.most_common(1)

    # Identify suspicious activity
    suspicious_ips = {ip: count for ip, count in failed_Logins.items() if count > failedLogin_threshold}

    return ip_Requests, endpoint_Requests, most_accessed_endpoint, suspicious_ips

# Function to save results to a CSV file
def save_to_csv(output_file_, ip_Requests, most_accessed_endpoint, suspicious_ips):
    with open(output_file_, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Write requests per IP
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_Requests.items():
            writer.writerow([ip, count])

        # Write most accessed endpoint
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint", "Access Count"])
        if most_accessed_endpoint:
            writer.writerow([most_accessed_endpoint[0][0], most_accessed_endpoint[0][1]])

        # Write suspicious activity
        writer.writerow([])
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])

# Main execution
if __name__ == "__main__":
    ip_Requests, endpoint_Requests, most_accessed_endpoint, suspicious_ips = analyze_log(log_file_)

    # Display results
    print("IP Address           Request Count")
    for ip, count in ip_Requests.most_common():
        print(f"{ip:<20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    if most_accessed_endpoint:
        endpoint, count = most_accessed_endpoint[0]
        print(f"{endpoint} (Accessed {count} times)")

    print("\nSuspicious Activity Detected:")
    if suspicious_ips:
        print(f"{'IP Address':<20} {'Failed Login Attempts'}")
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20} {count}")
    else:
        print("No suspicious activity detected.")

    # Save results to CSV
    save_to_csv(output_file_, ip_Requests, most_accessed_endpoint, suspicious_ips)
    print(f"\nResults saved to {output_file_}")