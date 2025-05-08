import os
import subprocess
import glob
import io
import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt


def consolidate_csv(pattern):
    data_suffix="_data.csv"
    header_suffix="_header.csv"
    files = glob.glob(pattern)
    dfs = []
    for file in files:
        # Derive header filename: replace the data_suffix with header_suffix
        header_file = file.replace(data_suffix, header_suffix)
        if os.path.exists(header_file):
            # use header.csv to name columns
            with open(header_file, 'r') as hf:
                header_line = hf.readline().strip()
                columns = header_line.split(',')
            df = pd.read_csv(file, header=None, names=columns)
            dfs.append(df)
        else:
            print(f"Header file {header_file} not found for data file {data_file}.")
    if dfs:
        return pd.concat(dfs, ignore_index=True)
    else:
        return pd.DataFrame()
    
def process_cpg_folders(directory):
    cpg_df = {}
    for folder in os.listdir(directory):
        # ignore joern folder 'workspace'
        if folder == "workspace": continue
        folder_path = os.path.join(directory, folder)
        if os.path.isdir(folder_path):
            #print(f"Processing folder: {folder}")
            # Build glob patterns for node and edge data files
            nodes_pattern = os.path.join(folder_path, "nodes_*_data.csv")
            edges_pattern = os.path.join(folder_path, "edges_*_data.csv")
            
            nodes_df = consolidate_csv(nodes_pattern)
            edges_df = consolidate_csv(edges_pattern)
            
            cpg_df[folder] = {"nodes": nodes_df, "edges": edges_df}
    return cpg_df

def print_dataframe_shapes(dict1, dict2, keys):
    # Print header
    print(f"{'cpg':<20} {'vuln nodes':<15} {'ptchd nodes':<15} {'vuln edges':<15} {'ptchd edges':<15}")
    print("-" * 80)
    
    # Print shapes for each key
    for key in keys:
        dict1_item1_shape = "Not found"
        dict1_item2_shape = "Not found"
        dict2_item1_shape = "Not found"
        dict2_item2_shape = "Not found"
        
        # Get shapes from dict1
        if key in dict1:
            nested_dict1 = dict1[key]
            if len(nested_dict1) == 2:
                nested_keys = list(nested_dict1.keys())
                dict1_item1_shape = str(nested_dict1[nested_keys[0]].shape)
                dict1_item2_shape = str(nested_dict1[nested_keys[1]].shape)
        
        # Get shapes from dict2
        if key in dict2:
            nested_dict2 = dict2[key]
            if len(nested_dict2) == 2:
                nested_keys = list(nested_dict2.keys())
                dict2_item1_shape = str(nested_dict2[nested_keys[0]].shape)
                dict2_item2_shape = str(nested_dict2[nested_keys[1]].shape)
        
        print(f"{key:<20} {dict1_item1_shape:<15} {dict2_item1_shape:<15} {dict1_item2_shape:<15} {dict2_item2_shape:<15}")

def cpg_compare_counts(df1, df2):
    # Capture output for first dataframe
    buffer1 = io.StringIO()
    df1.info(buf=buffer1)
    info1 = buffer1.getvalue().splitlines()

    # Capture output for second dataframe
    buffer2 = io.StringIO()
    df2.info(buf=buffer2)
    info2 = buffer2.getvalue().splitlines()

    # Determine maximum number of lines
    max_lines = max(len(info1), len(info2))

    # Print the outputs side by side
    for i in range(max_lines):
        left = info1[i] if i < len(info1) else ""
        right = info2[i] if i < len(info2) else ""
        print(f"{left:<50} {right}")

def build_graph(cpg: dict, subgraph: str) -> nx.DiGraph:
    subgraph = subgraph.upper()
    graph = nx.DiGraph()

    edges = cpg["edges"]
    edges = edges[edges[':TYPE'] == subgraph]

    sub_nodes = set(edges[':START_ID']).union(set(edges[':END_ID']))

    for node in sub_nodes:
        node_attr = {}
        if node in cpg["nodes"][":ID"].values:
            node_attr = cpg['nodes'][cpg['nodes'][':ID'] == node].iloc[0].to_dict()
        graph.add_node(node, **node_attr)

    for _, row in edges.iterrows():
        src = row[':START_ID']
        tgt = row[':END_ID']
        graph.add_edge(src, tgt, **row.to_dict())

    return graph

def visualize_graph(graph, feature):
    labels = {node: data.get(feature, node) for node, data in graph.nodes(data=True)}
    fig, ax = plt.subplots(figsize=(10, 8))
    pos = nx.spring_layout(graph, seed=42)
    nx.draw(graph, pos, labels=labels, with_labels=True, ax=ax, node_color='orange', arrows=True)
    plt.show()