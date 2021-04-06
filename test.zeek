#a global variable to store the relationship of sourceIP to user-agent
global agent_table: table[addr] of set[string] = table();

#a event which can return the http header user_agent information
event http_header(c: connection, is_orig: bool, name: string, value: string) {
    local source_ip: addr = c$id$orig_h;
    
    if (c$http?$user_agent) {
    #to_lower(str) return a lowercase version string of the original one
        local agent: string = to_lower(c$http$user_agent);
        
        if (source_ip in agent_table) {
            add (agent_table[source_ip])[agent];
        } 
        
        else {
            agent_table[source_ip] = set(agent);
        }
    }
}

event zeek_done() {
    for (source_ip in agent_table) {
    # if a source IP is related to three different user-agents or more
        if (|agent_table[source_ip]| >= 3) {
        #output “xxx.xxx.xxx.xxx is a proxy” where xxx.xxx.xxx.xxx is the source IP
            print(addr_to_uri(source_ip) + " is a proxy");
        }
    }
}
