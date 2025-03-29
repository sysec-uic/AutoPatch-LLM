from dataclasses import dataclass, field

@dataclass
class CpgDetail:
    graph: dict = field(default_factory=dict)
    # vuln (vulnerable) - boolean flag indicating whether a CVE has been detected in this cpg
    vuln: bool
    # vuln_type - classification of detected vulnerability
    vuln_type: str
    


    def add_node(self, node):
        if node not in self.graph:
            self.graph[node] = set()

    def add_edge(self, node1, node2):
        self.add_node(node1)
        self.add_node(node2)
        # Add the edge in both directions
        self.graph[node1].add(node2)
        self.graph[node2].add(node1)

    def get_neighbors(self, node):
        return self.graph.get(node, set())

    def has_node(self, node):
        """Return True if the node exists in the graph."""
        return node in self.graph
    
    def has_edge(self, node1, node2):
       """Return True if there is an edge between node1 and node2."""
       return node1 in self.graph and node2 in self.graph[node1]
    
    def nodes(self):
        """Return a list of all nodes in the graph."""
        return list(self.graph.keys())
    
    def edges(self):
        """
        Return a list of edges in the graph as tuples (node1, node2).
        Each undirected edge appears only once.
        """
        seen = set()
        edge_list = []
        for node, neighbors in self.graph.items():
            for neighbor in neighbors:
                edge = frozenset((node, neighbor))
                if edge not in seen:
                    seen.add(edge)
                    edge_list.append((node, neighbor))
        return edge_list

    # TODO Maybe we don't need this 
    # def degree(self, node):
    #     """Return the degree (number of neighbors) of the given node."""
    #     return len(self.get_neighbors(node))


    # TODO Maybe we don't need this 
    def connected_components(self):
        """
        Return a list of sets, each set being the nodes in a connected component.
        Uses a simple breadth-first search.
        """
        # if we are doign a BFS, use a deque
        pass
