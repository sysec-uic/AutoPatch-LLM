import pytest
from dataclasses import dataclass, field

# The class under test. In a real-world scenario, this would be imported from your module.
@dataclass
class CpgDetail:
    graph: dict = field(default_factory=dict)

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

    def connected_components(self):
        """
        Return a list of sets, each set being the nodes in a connected component.
        Uses a simple breadth-first search.
        """
        # Not implemented
        pass

# --------------------- Tests using pytest ---------------------

def test_empty_graph():
    """Test that a new graph has no nodes or edges."""
    cpg = CpgDetail()
    assert cpg.nodes() == []
    assert cpg.edges() == []

def test_add_node():
    """Test adding a single node."""
    cpg = CpgDetail()
    cpg.add_node('A')
    assert cpg.has_node('A')
    assert cpg.get_neighbors('A') == set()

def test_duplicate_node_addition():
    """Test that adding the same node twice does not create duplicates."""
    cpg = CpgDetail()
    cpg.add_node('A')
    cpg.add_node('A')
    # Only one instance of the node should exist.
    assert len(cpg.nodes()) == 1

def test_add_edge():
    """Test adding an edge and verifying bidirectional connection."""
    cpg = CpgDetail()
    cpg.add_edge('A', 'B')
    assert cpg.has_edge('A', 'B')
    assert cpg.has_edge('B', 'A')
    assert cpg.get_neighbors('A') == {'B'}
    assert cpg.get_neighbors('B') == {'A'}

def test_edges_no_duplicates():
    """Test that adding the same edge twice does not result in duplicate edges."""
    cpg = CpgDetail()
    cpg.add_edge('A', 'B')
    cpg.add_edge('A', 'B')  # Add duplicate edge
    edges = cpg.edges()
    # There should be exactly one edge (in either direction).
    assert len(edges) == 1
    # Use frozenset to ensure the undirected edge is correctly formed.
    assert frozenset(edges[0]) == frozenset(('A', 'B'))

def test_nodes_listing():
    """Test that all added nodes are returned, regardless of the order."""
    cpg = CpgDetail()
    nodes = ['A', 'B', 'C']
    for node in nodes:
        cpg.add_node(node)
    cpg.add_edge('B', 'C')  # Adding an edge between existing nodes.
    returned_nodes = cpg.nodes()
    assert set(returned_nodes) == set(nodes)

def test_get_neighbors_nonexistent():
    """Test that asking for neighbors of a non-existent node returns an empty set."""
    cpg = CpgDetail()
    assert cpg.get_neighbors('NonExistent') == set()

def test_has_edge_nonexistent():
    """Test that has_edge returns False if nodes or edges are missing."""
    cpg = CpgDetail()
    cpg.add_node('A')
    # 'B' has not been added
    assert not cpg.has_edge('A', 'B')
    assert not cpg.has_edge('B', 'A')

def test_edge_multiple_edges():
    """Test multiple edges in a more complex graph structure."""
    cpg = CpgDetail()
    cpg.add_edge('A', 'B')
    cpg.add_edge('A', 'C')
    cpg.add_edge('B', 'C')
    # Expected undirected edges: A-B, A-C, and B-C
    expected_edges = {frozenset(('A', 'B')), frozenset(('A', 'C')), frozenset(('B', 'C'))}
    actual_edges = {frozenset(edge) for edge in cpg.edges()}
    assert actual_edges == expected_edges

def test_add_node_with_non_hashable():
    """Test that adding an unhashable node raises a TypeError."""
    cpg = CpgDetail()
    with pytest.raises(TypeError):
        cpg.add_node([])  # lists are unhashable

def test_add_edge_with_non_hashable():
    """Test that adding an edge with an unhashable node raises a TypeError."""
    cpg = CpgDetail()
    with pytest.raises(TypeError):
        cpg.add_edge('A', [])  # second node is unhashable

def test_connected_components_stub():
    """Test that the unimplemented connected_components method returns None."""
    cpg = CpgDetail()
    assert cpg.connected_components() is None
