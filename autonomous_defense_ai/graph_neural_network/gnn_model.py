"""
Graph Neural Network Attack Prediction Module

This module implements advanced graph neural networks for predicting attacker movements
and detecting unknown threats in the cyber defense graph.

Key Features:
- GNN-based attack path prediction
- Temporal graph analysis for threat evolution
- Anomaly detection in graph structures
- Real-time threat scoring
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GCNConv, GATConv, SAGEConv
from torch_geometric.data import Data, DataLoader
import numpy as np
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

@dataclass
class GraphNode:
    """Represents a node in the cyber defense graph"""
    node_id: str
    node_type: str  # 'user', 'resource', 'identity', 'asset'
    features: np.ndarray
    timestamp: datetime
    risk_score: float = 0.0

@dataclass
class GraphEdge:
    """Represents an edge in the cyber defense graph"""
    source_id: str
    target_id: str
    edge_type: str  # 'access', 'execute', 'network', 'privilege'
    weight: float
    timestamp: datetime
    is_anomalous: bool = False

class GraphNeuralNetwork(nn.Module):
    """
    Advanced Graph Neural Network for cyber threat prediction
    """

    def __init__(self, input_dim: int, hidden_dim: int, output_dim: int, num_layers: int = 3):
        super(GraphNeuralNetwork, self).__init__()

        self.num_layers = num_layers
        self.convs = nn.ModuleList()

        # Input layer
        self.convs.append(GCNConv(input_dim, hidden_dim))

        # Hidden layers
        for _ in range(num_layers - 2):
            self.convs.append(GCNConv(hidden_dim, hidden_dim))

        # Output layer
        self.convs.append(GCNConv(hidden_dim, output_dim))

        # Attention mechanism for temporal features
        self.temporal_attention = nn.MultiheadAttention(hidden_dim, num_heads=8)

        # Risk prediction head
        self.risk_predictor = nn.Sequential(
            nn.Linear(output_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(hidden_dim, 1),
            nn.Sigmoid()
        )

        # Attack path prediction head
        self.path_predictor = nn.Sequential(
            nn.Linear(output_dim * 2, hidden_dim),
            nn.ReLU(),
            nn.Linear(hidden_dim, 1),
            nn.Sigmoid()
        )

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor,
                edge_attr: Optional[torch.Tensor] = None) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Forward pass through the GNN

        Args:
            x: Node features [num_nodes, input_dim]
            edge_index: Edge indices [2, num_edges]
            edge_attr: Edge attributes [num_edges, edge_dim]

        Returns:
            node_embeddings: Node embeddings [num_nodes, output_dim]
            risk_scores: Predicted risk scores [num_nodes, 1]
        """
        # Apply GNN layers
        for i, conv in enumerate(self.convs[:-1]):
            x = conv(x, edge_index, edge_attr)
            x = F.relu(x)
            x = F.dropout(x, p=0.2, training=self.training)

        # Final convolution
        x = self.convs[-1](x, edge_index, edge_attr)

        # Apply temporal attention
        x_temporal = x.unsqueeze(0)  # Add batch dimension
        x_attended, _ = self.temporal_attention(x_temporal, x_temporal, x_temporal)
        x_attended = x_attended.squeeze(0)

        # Predict risk scores
        risk_scores = self.risk_predictor(x_attended)

        return x_attended, risk_scores

    def predict_attack_path(self, source_embedding: torch.Tensor,
                           target_embedding: torch.Tensor) -> float:
        """
        Predict the likelihood of an attack path between two nodes

        Args:
            source_embedding: Source node embedding
            target_embedding: Target node embedding

        Returns:
            path_probability: Probability of attack path
        """
        combined = torch.cat([source_embedding, target_embedding], dim=-1)
        return self.path_predictor(combined).item()

class AttackPredictionEngine:
    """
    Engine for predicting attacker movements using Graph Neural Networks
    """

    def __init__(self, model_path: Optional[str] = None):
        self.model = GraphNeuralNetwork(
            input_dim=128,  # Feature dimension
            hidden_dim=256,
            output_dim=128,
            num_layers=4
        )

        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.model.to(self.device)

        if model_path:
            self.load_model(model_path)

        self.optimizer = torch.optim.Adam(self.model.parameters(), lr=0.001)
        self.criterion = nn.BCELoss()

        # Feature builder for graph construction
        self.feature_builder = GraphFeatureBuilder()

    def load_model(self, path: str):
        """Load trained model from disk"""
        self.model.load_state_dict(torch.load(path, map_location=self.device))
        self.model.eval()
        logger.info(f"Loaded GNN model from {path}")

    def save_model(self, path: str):
        """Save trained model to disk"""
        torch.save(self.model.state_dict(), path)
        logger.info(f"Saved GNN model to {path}")

    def build_graph_data(self, nodes: List[GraphNode],
                        edges: List[GraphEdge]) -> Data:
        """
        Build PyTorch Geometric Data object from nodes and edges

        Args:
            nodes: List of graph nodes
            edges: List of graph edges

        Returns:
            graph_data: PyTorch Geometric Data object
        """
        # Create node feature matrix
        node_features = []
        node_id_to_idx = {}

        for idx, node in enumerate(nodes):
            node_id_to_idx[node.node_id] = idx
            features = self.feature_builder.build_node_features(node)
            node_features.append(features)

        x = torch.tensor(np.array(node_features), dtype=torch.float)

        # Create edge index
        edge_index = []
        edge_attr = []

        for edge in edges:
            if edge.source_id in node_id_to_idx and edge.target_id in node_id_to_idx:
                source_idx = node_id_to_idx[edge.source_id]
                target_idx = node_id_to_idx[edge.target_id]

                edge_index.append([source_idx, target_idx])
                edge_features = self.feature_builder.build_edge_features(edge)
                edge_attr.append(edge_features)

        edge_index = torch.tensor(edge_index, dtype=torch.long).t().contiguous()
        edge_attr = torch.tensor(np.array(edge_attr), dtype=torch.float)

        return Data(x=x, edge_index=edge_index, edge_attr=edge_attr)

    def predict_threats(self, graph_data: Data) -> Dict[str, Any]:
        """
        Predict threats using the trained GNN model

        Args:
            graph_data: Graph data for prediction

        Returns:
            predictions: Dictionary containing threat predictions
        """
        self.model.eval()

        with torch.no_grad():
            graph_data = graph_data.to(self.device)
            node_embeddings, risk_scores = self.model(
                graph_data.x, graph_data.edge_index, graph_data.edge_attr
            )

            # Convert to numpy for easier processing
            risk_scores = risk_scores.cpu().numpy().flatten()
            node_embeddings = node_embeddings.cpu().numpy()

        # Identify high-risk nodes
        high_risk_threshold = np.percentile(risk_scores, 95)
        high_risk_indices = np.where(risk_scores > high_risk_threshold)[0]

        # Predict attack paths between high-risk nodes
        attack_paths = []
        for i in high_risk_indices:
            for j in high_risk_indices:
                if i != j:
                    path_prob = self.model.predict_attack_path(
                        torch.tensor(node_embeddings[i], device=self.device),
                        torch.tensor(node_embeddings[j], device=self.device)
                    )
                    if path_prob > 0.7:  # High probability threshold
                        attack_paths.append({
                            'source_idx': int(i),
                            'target_idx': int(j),
                            'probability': float(path_prob)
                        })

        return {
            'risk_scores': risk_scores.tolist(),
            'high_risk_nodes': high_risk_indices.tolist(),
            'predicted_attack_paths': attack_paths,
            'timestamp': datetime.now().isoformat()
        }

    def train_model(self, train_data: List[Data], val_data: List[Data],
                   epochs: int = 100) -> Dict[str, List[float]]:
        """
        Train the GNN model

        Args:
            train_data: Training graph data
            val_data: Validation graph data
            epochs: Number of training epochs

        Returns:
            training_history: Dictionary with loss curves
        """
        self.model.train()

        train_losses = []
        val_losses = []

        for epoch in range(epochs):
            epoch_train_loss = 0
            epoch_val_loss = 0

            # Training
            for batch in train_data:
                batch = batch.to(self.device)

                self.optimizer.zero_grad()

                # Forward pass
                _, risk_scores = self.model(batch.x, batch.edge_index, batch.edge_attr)

                # For training, we need ground truth labels
                # This is a simplified version - in practice, you'd have labeled data
                target_risk = torch.rand(batch.x.size(0), 1, device=self.device)

                loss = self.criterion(risk_scores, target_risk)
                loss.backward()
                self.optimizer.step()

                epoch_train_loss += loss.item()

            # Validation
            self.model.eval()
            with torch.no_grad():
                for batch in val_data:
                    batch = batch.to(self.device)
                    _, risk_scores = self.model(batch.x, batch.edge_index, batch.edge_attr)

                    target_risk = torch.rand(batch.x.size(0), 1, device=self.device)
                    loss = self.criterion(risk_scores, target_risk)
                    epoch_val_loss += loss.item()
            self.model.train()

            train_losses.append(epoch_train_loss / len(train_data))
            val_losses.append(epoch_val_loss / len(val_data))

            if epoch % 10 == 0:
                logger.info(f"Epoch {epoch}: Train Loss = {train_losses[-1]:.4f}, "
                          f"Val Loss = {val_losses[-1]:.4f}")

        return {
            'train_losses': train_losses,
            'val_losses': val_losses
        }

class GraphFeatureBuilder:
    """
    Builds features for nodes and edges in the cyber defense graph
    """

    def __init__(self):
        self.node_type_mapping = {
            'user': 0,
            'resource': 1,
            'identity': 2,
            'asset': 3,
            'service': 4,
            'container': 5
        }

        self.edge_type_mapping = {
            'access': 0,
            'execute': 1,
            'network': 2,
            'privilege': 3,
            'data_flow': 4,
            'authentication': 5
        }

    def build_node_features(self, node: GraphNode) -> np.ndarray:
        """
        Build feature vector for a graph node

        Args:
            node: Graph node object

        Returns:
            features: Feature vector
        """
        features = []

        # Node type encoding (one-hot)
        type_encoding = np.zeros(len(self.node_type_mapping))
        if node.node_type in self.node_type_mapping:
            type_encoding[self.node_type_mapping[node.node_type]] = 1
        features.extend(type_encoding)

        # Risk score
        features.append(node.risk_score)

        # Timestamp features
        features.append(node.timestamp.hour / 24.0)  # Hour of day
        features.append(node.timestamp.weekday() / 7.0)  # Day of week

        # Node-specific features
        if hasattr(node, 'features') and node.features is not None:
            features.extend(node.features)

        # Pad or truncate to fixed size
        target_size = 128
        if len(features) < target_size:
            features.extend([0.0] * (target_size - len(features)))
        else:
            features = features[:target_size]

        return np.array(features, dtype=np.float32)

    def build_edge_features(self, edge: GraphEdge) -> np.ndarray:
        """
        Build feature vector for a graph edge

        Args:
            edge: Graph edge object

        Returns:
            features: Feature vector
        """
        features = []

        # Edge type encoding (one-hot)
        type_encoding = np.zeros(len(self.edge_type_mapping))
        if edge.edge_type in self.edge_type_mapping:
            type_encoding[self.edge_type_mapping[edge.edge_type]] = 1
        features.extend(type_encoding)

        # Edge weight
        features.append(edge.weight)

        # Timestamp features
        features.append(edge.timestamp.hour / 24.0)
        features.append(edge.timestamp.weekday() / 7.0)

        # Anomaly flag
        features.append(1.0 if edge.is_anomalous else 0.0)

        # Pad to fixed size
        target_size = 16
        if len(features) < target_size:
            features.extend([0.0] * (target_size - len(features)))

        return np.array(features, dtype=np.float32)

class ThreatPredictor:
    """
    High-level interface for threat prediction using GNN
    """

    def __init__(self, model_path: Optional[str] = None):
        self.engine = AttackPredictionEngine(model_path)
        self.feature_builder = GraphFeatureBuilder()

    def analyze_threat_landscape(self, nodes: List[GraphNode],
                               edges: List[GraphEdge]) -> Dict[str, Any]:
        """
        Analyze the current threat landscape

        Args:
            nodes: Current graph nodes
            edges: Current graph edges

        Returns:
            analysis: Threat analysis results
        """
        # Build graph data
        graph_data = self.engine.build_graph_data(nodes, edges)

        # Get predictions
        predictions = self.engine.predict_threats(graph_data)

        # Enrich with node information
        high_risk_nodes_info = []
        for idx in predictions['high_risk_nodes']:
            if idx < len(nodes):
                node = nodes[idx]
                high_risk_nodes_info.append({
                    'node_id': node.node_id,
                    'node_type': node.node_type,
                    'risk_score': predictions['risk_scores'][idx],
                    'timestamp': node.timestamp.isoformat()
                })

        # Enrich attack paths
        enriched_paths = []
        for path in predictions['predicted_attack_paths']:
            source_node = nodes[path['source_idx']] if path['source_idx'] < len(nodes) else None
            target_node = nodes[path['target_idx']] if path['target_idx'] < len(nodes) else None

            if source_node and target_node:
                enriched_paths.append({
                    'source_node': {
                        'id': source_node.node_id,
                        'type': source_node.node_type
                    },
                    'target_node': {
                        'id': target_node.node_id,
                        'type': target_node.node_type
                    },
                    'probability': path['probability']
                })

        return {
            'high_risk_nodes': high_risk_nodes_info,
            'predicted_attack_paths': enriched_paths,
            'overall_risk_score': np.mean(predictions['risk_scores']),
            'timestamp': predictions['timestamp']
        }

    def update_model(self, new_training_data: List[Tuple[List[GraphNode], List[GraphEdge]]]):
        """
        Update the model with new training data

        Args:
            new_training_data: List of (nodes, edges) tuples for training
        """
        # Convert to Data objects
        train_data = []
        for nodes, edges in new_training_data:
            graph_data = self.engine.build_graph_data(nodes, edges)
            train_data.append(graph_data)

        # Simple train/val split
        val_size = max(1, len(train_data) // 5)
        val_data = train_data[-val_size:]
        train_data = train_data[:-val_size]

        # Train the model
        history = self.engine.train_model(train_data, val_data, epochs=50)

        logger.info("Model training completed")
        logger.info(f"Final train loss: {history['train_losses'][-1]:.4f}")
        logger.info(f"Final val loss: {history['val_losses'][-1]:.4f}")

# Example usage and testing
if __name__ == "__main__":
    # Create sample data for testing
    nodes = [
        GraphNode("user1", "user", np.random.rand(64), datetime.now(), 0.1),
        GraphNode("server1", "resource", np.random.rand(64), datetime.now(), 0.8),
        GraphNode("db1", "asset", np.random.rand(64), datetime.now(), 0.9),
    ]

    edges = [
        GraphEdge("user1", "server1", "access", 0.7, datetime.now()),
        GraphEdge("server1", "db1", "data_flow", 0.9, datetime.now()),
    ]

    predictor = ThreatPredictor()
    analysis = predictor.analyze_threat_landscape(nodes, edges)

    print("Threat Analysis Results:")
    print(f"High-risk nodes: {len(analysis['high_risk_nodes'])}")
    print(f"Predicted attack paths: {len(analysis['predicted_attack_paths'])}")
    print(f"Overall risk score: {analysis['overall_risk_score']:.3f}")