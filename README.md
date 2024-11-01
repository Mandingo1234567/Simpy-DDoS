# Simpy: Simulation of Server Resilience: Comparing Load Balancing, Rate Limiting and WAF in DDOS Mitigation
import simpy
import random
import matplotlib.pyplot as plt

class Server:
    def __init__(self, env, protection):
        self.env = env
        self.protection = protection
        self.requests_processed = 0
        self.legit_times, self.attack_times = [], []

    def process_request(self, req_type):
        # Bestäm svarstid beroende på skydd och typ av förfrågan
        if self.protection == 'load_balancing':
            response_time = random.normalvariate(0.2, 0.05) if req_type == 'legitimate' else random.normalvariate(0.6, 0.2)
        elif self.protection == 'rate_limiting':
            response_time = random.normalvariate(0.25, 0.05) if req_type == 'legitimate' else random.expovariate(1 / 1.0)
        elif self.protection == 'waf':
            response_time = random.normalvariate(0.3, 0.05) if req_type == 'legitimate' else random.expovariate(1 / 1.2)
        else:
            response_time = random.normalvariate(0.3, 0.1) if req_type == 'legitimate' else random.expovariate(1 / 1.5)

        yield self.env.timeout(max(response_time, 0.01))  # Minimera svarstid till minst 0.01
        self.requests_processed += 1
        (self.legit_times if req_type == 'legitimate' else self.attack_times).append(response_time)

    def run(self):
        while True:
            yield self.env.timeout(random.uniform(0.05, 0.2))
            req_type = 'legitimate' if random.random() > 0.8 else 'attack'
            self.env.process(self.process_request(req_type))

class DDoSAttack:
    def __init__(self, env, server):
        self.env, self.server = env, server

    def launch(self):
        while True:
            yield self.env.timeout(random.uniform(0.01, 0.05))
            self.env.process(self.server.process_request('attack'))

def run_simulation(protection, sim_time):
    env = simpy.Environment()
    server = Server(env, protection)
    DDoSAttack(env, server).launch()  # Starta attack

    env.process(server.run())
    env.run(until=sim_time)
    return {
        'total_requests': server.requests_processed,
        'legit_times': server.legit_times,
        'attack_times': server.attack_times
    }

# Parametrar för simuleringen
tests, sim_time = 5, 30
results = {'load_balancing': [], 'rate_limiting': [], 'waf': []}

# Kör simulering och samlar resultat
for tech in results.keys():
    print(f"\n{tech.capitalize()} Simulation:")
    for i in range(tests):
        data = run_simulation(tech, sim_time)
        avg_legit = sum(data['legit_times']) / len(data['legit_times']) if data['legit_times'] else 0
        avg_attack = sum(data['attack_times']) / len(data['attack_times']) if data['attack_times'] else 0
        max_time = max(data['legit_times'] + data['attack_times'], default=0)
        legit_ratio = len(data['legit_times']) / data['total_requests'] if data['total_requests'] else 0
        
        # Logga resultat
        results[tech].append({
            'total_requests': data['total_requests'],
            'avg_legit_time': avg_legit,
            'avg_attack_time': avg_attack,
            'max_time': max_time,
            'legit_ratio': legit_ratio
        })
        print(f"Test {i+1}: Requests: {data['total_requests']}, Avg Legit Time: {avg_legit:.2f}s, "
              f"Avg Attack Time: {avg_attack:.2f}s, Max Time: {max_time:.2f}s, Legit Ratio: {legit_ratio:.2f}")

# Summering
print("\nResultatsammanfattning:")
for tech, metrics in results.items():
    avg_legit = sum(m['avg_legit_time'] for m in metrics) / tests
    avg_attack = sum(m['avg_attack_time'] for m in metrics) / tests
    avg_max = sum(m['max_time'] for m in metrics) / tests
    avg_ratio = sum(m['legit_ratio'] for m in metrics) / tests
    total_requests = sum(m['total_requests'] for m in metrics)
    print(f"{tech.capitalize()}: Total Requests: {total_requests}, Avg Legit Time: {avg_legit:.2f}s, "
          f"Avg Attack Time: {avg_attack:.2f}s, Max Time: {avg_max:.2f}s, Legit Ratio: {avg_ratio:.2f}")

# Funktion för att rita histogram
def plot_histograms(results):
    plt.figure(figsize=(15, 10))

    for i, (tech, metrics) in enumerate(results.items()):
        legit_times = [m['avg_legit_time'] for m in metrics if m['avg_legit_time'] > 0]
        attack_times = [m['avg_attack_time'] for m in metrics if m['avg_attack_time'] > 0]

        plt.subplot(3, 2, i * 2 + 1)
        plt.hist(legit_times, bins=10, alpha=0.7, color='blue', edgecolor='black')
        plt.title(f'Legitimate Response Times - {tech.capitalize()}')
        plt.xlabel('Response Time (s)')
        plt.ylabel('Frequency')

        plt.subplot(3, 2, i * 2 + 2)
        plt.hist(attack_times, bins=10, alpha=0.7, color='red', edgecolor='black')
        plt.title(f'Attack Response Times - {tech.capitalize()}')
        plt.xlabel('Response Time (s)')
        plt.ylabel('Frequency')

    plt.tight_layout()
    plt.show()

# Plotta histogram
plot_histograms(results)
