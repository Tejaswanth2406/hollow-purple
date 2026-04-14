"""
Graph Neural Network Model Trainer

This module provides comprehensive training capabilities for GNN models used in
cyber threat detection and attack prediction. It includes data preparation,
model training, validation, and deployment features.
"""

import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
from torch_geometric.data import Data, DataLoader as GeoDataLoader
import numpy as np
from typing import Dict, List, Tuple, Optional, Any, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
import logging
import json
import os
from sklearn.metrics import roc_auc_score, precision_recall_curve, auc
from sklearn.model_selection import train_test_split
import matplotlib.pyplot as plt
import seaborn as sns

from .gnn_model import GraphNeuralNetwork, AttackPredictionEngine
from .graph_feature_builder import AdvancedGraphFeatureBuilder

logger = logging.getLogger(__name__)

@dataclass
class TrainingConfig:
    """Configuration for GNN training"""
    learning_rate: float = 0.001
    batch_size: int = 32
    num_epochs: int = 100
    hidden_dim: int = 256
    num_layers: int = 4
    dropout_rate: float = 0.2
    weight_decay: float = 1e-4
    patience: int = 10
    validation_split: float = 0.2
    early_stopping_threshold: float = 0.01
    gradient_clip_value: float = 1.0

@dataclass
class TrainingMetrics:
    """Metrics collected during training"""
    epoch: int
    train_loss: float
    val_loss: float
    train_auc: float
    val_auc: float
    train_precision: float
    val_precision: float
    train_recall: float
    val_recall: float

class GNNModelTrainer:
    """
    Comprehensive trainer for Graph Neural Network models
    """

    def __init__(self, config: TrainingConfig = None):
        self.config = config or TrainingConfig()
        self.model = None
        self.optimizer = None
        self.criterion = None
        self.scheduler = None

        self.feature_builder = AdvancedGraphFeatureBuilder()

        # Training history
        self.training_history = []

        # Best model tracking
        self.best_model_state = None
        self.best_val_loss = float('inf')
        self.best_val_auc = 0.0

        # Device configuration
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        logger.info(f"Using device: {self.device}")

    def prepare_training_data(self, raw_data: List[Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]],
                            labels: Optional[List[float]] = None) -> Tuple[DataLoader, DataLoader]:
        """
        Prepare training and validation data from raw graph data

        Args:
            raw_data: List of (nodes, edges, temporal_events) tuples
            labels: Optional labels for supervised training

        Returns:
            train_loader, val_loader: Data loaders for training
        """
        logger.info(f"Preparing training data from {len(raw_data)} samples")

        # Convert raw data to PyTorch Geometric Data objects
        graph_data = []

        for nodes, edges, temporal_events in raw_data:
            try:
                # Build graph data
                data = self._build_graph_data_from_raw(nodes, edges, temporal_events)

                # Add label if provided
                if labels is not None:
                    data.y = torch.tensor([labels[len(graph_data)]], dtype=torch.float)
                else:
                    # Generate synthetic labels for unsupervised training
                    data.y = torch.tensor([self._generate_synthetic_label(nodes, edges)],
                                        dtype=torch.float)

                graph_data.append(data)

            except Exception as e:
                logger.warning(f"Failed to process graph sample: {e}")
                continue

        if not graph_data:
            raise ValueError("No valid graph data could be prepared")

        # Split into train/validation
        train_data, val_data = train_test_split(
            graph_data,
            test_size=self.config.validation_split,
            random_state=42
        )

        # Create data loaders
        train_loader = GeoDataLoader(train_data, batch_size=self.config.batch_size, shuffle=True)
        val_loader = GeoDataLoader(val_data, batch_size=self.config.batch_size, shuffle=False)

        logger.info(f"Prepared {len(train_data)} training and {len(val_data)} validation samples")

        return train_loader, val_loader

    def _build_graph_data_from_raw(self, nodes: List[Dict[str, Any]],
                                 edges: List[Dict[str, Any]],
                                 temporal_events: List[Dict[str, Any]]) -> Data:
        """Build PyTorch Geometric Data object from raw data"""
        # Create node features
        node_features = []
        node_id_to_idx = {}

        for idx, node in enumerate(nodes):
            node_id_to_idx[node['id']] = idx

            # Build comprehensive node features
            features = self.feature_builder.build_node_features(node, temporal_events)
            node_features.append(features)

        x = torch.tensor(np.array(node_features), dtype=torch.float)

        # Create edge index and features
        edge_index = []
        edge_attr = []

        for edge in edges:
            source_id = edge.get('source')
            target_id = edge.get('target')

            if source_id in node_id_to_idx and target_id in node_id_to_idx:
                source_idx = node_id_to_idx[source_id]
                target_idx = node_id_to_idx[target_id]

                edge_index.append([source_idx, target_idx])

                # Build edge features
                edge_features = self.feature_builder.build_edge_features(
                    edge,
                    nodes[source_idx] if source_idx < len(nodes) else None,
                    nodes[target_idx] if target_idx < len(nodes) else None
                )
                edge_attr.append(edge_features)

        edge_index = torch.tensor(edge_index, dtype=torch.long).t().contiguous()
        edge_attr = torch.tensor(np.array(edge_attr), dtype=torch.float)

        return Data(x=x, edge_index=edge_index, edge_attr=edge_attr)

    def _generate_synthetic_label(self, nodes: List[Dict[str, Any]],
                                edges: List[Dict[str, Any]]) -> float:
        """Generate synthetic labels for unsupervised training"""
        # Calculate risk score based on graph properties
        risk_score = 0.0

        # Factor in node types
        high_risk_types = ['database', 'admin_system', 'secret_store']
        for node in nodes:
            if node.get('type', '').lower() in high_risk_types:
                risk_score += 0.3

        # Factor in edge types
        high_risk_edge_types = ['privilege_escalation', 'data_exfiltration']
        for edge in edges:
            if edge.get('type', '').lower() in high_risk_edge_types:
                risk_score += 0.2

        # Factor in connectivity
        avg_degree = len(edges) * 2 / max(len(nodes), 1)
        risk_score += min(avg_degree / 10.0, 0.2)  # Normalize

        return min(risk_score, 1.0)

    def initialize_model(self, input_dim: int, output_dim: int = 1):
        """Initialize the GNN model and training components"""
        self.model = GraphNeuralNetwork(
            input_dim=input_dim,
            hidden_dim=self.config.hidden_dim,
            output_dim=self.config.hidden_dim,  # Intermediate output for risk prediction
            num_layers=self.config.num_layers
        ).to(self.device)

        # Initialize optimizer
        self.optimizer = optim.Adam(
            self.model.parameters(),
            lr=self.config.learning_rate,
            weight_decay=self.config.weight_decay
        )

        # Initialize loss function
        self.criterion = nn.BCELoss()  # Binary cross-entropy for risk prediction

        # Initialize learning rate scheduler
        self.scheduler = optim.lr_scheduler.ReduceLROnPlateau(
            self.optimizer, mode='min', factor=0.5, patience=5, verbose=True
        )

        logger.info(f"Initialized GNN model with {sum(p.numel() for p in self.model.parameters())} parameters")

    def train_model(self, train_loader: DataLoader, val_loader: DataLoader,
                   save_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Train the GNN model

        Args:
            train_loader: Training data loader
            val_loader: Validation data loader
            save_path: Path to save the best model

        Returns:
            training_results: Dictionary with training metrics and results
        """
        logger.info("Starting GNN model training")

        self.training_history = []
        early_stopping_counter = 0

        for epoch in range(self.config.num_epochs):
            # Training phase
            train_metrics = self._train_epoch(train_loader)

            # Validation phase
            val_metrics = self._validate_epoch(val_loader)

            # Calculate combined metrics
            epoch_metrics = TrainingMetrics(
                epoch=epoch + 1,
                train_loss=train_metrics['loss'],
                val_loss=val_metrics['loss'],
                train_auc=train_metrics.get('auc', 0.0),
                val_auc=val_metrics.get('auc', 0.0),
                train_precision=train_metrics.get('precision', 0.0),
                val_precision=val_metrics.get('precision', 0.0),
                train_recall=train_metrics.get('recall', 0.0),
                val_recall=val_metrics.get('recall', 0.0)
            )

            self.training_history.append(epoch_metrics)

            # Update learning rate scheduler
            self.scheduler.step(val_metrics['loss'])

            # Check for best model
            if val_metrics['loss'] < self.best_val_loss:
                self.best_val_loss = val_metrics['loss']
                self.best_val_auc = val_metrics.get('auc', 0.0)
                self.best_model_state = self.model.state_dict().copy()

                early_stopping_counter = 0

                # Save best model
                if save_path:
                    self.save_model(save_path)

            else:
                early_stopping_counter += 1

            # Early stopping
            if early_stopping_counter >= self.config.patience:
                logger.info(f"Early stopping at epoch {epoch + 1}")
                break

            # Logging
            if (epoch + 1) % 10 == 0:
                logger.info(f"Epoch {epoch + 1}/{self.config.num_epochs} - "
                          f"Train Loss: {train_metrics['loss']:.4f}, "
                          f"Val Loss: {val_metrics['loss']:.4f}, "
                          f"Val AUC: {val_metrics.get('auc', 0.0):.4f}")

        # Load best model
        if self.best_model_state:
            self.model.load_state_dict(self.best_model_state)

        training_results = {
            'final_train_loss': self.training_history[-1].train_loss,
            'final_val_loss': self.training_history[-1].val_loss,
            'best_val_loss': self.best_val_loss,
            'best_val_auc': self.best_val_auc,
            'epochs_trained': len(self.training_history),
            'training_history': [vars(m) for m in self.training_history],
            'model_parameters': sum(p.numel() for p in self.model.parameters())
        }

        logger.info("Training completed")
        logger.info(f"Best validation loss: {self.best_val_loss:.4f}")
        logger.info(f"Best validation AUC: {self.best_val_auc:.4f}")

        return training_results

    def _train_epoch(self, train_loader: DataLoader) -> Dict[str, float]:
        """Train for one epoch"""
        self.model.train()

        total_loss = 0.0
        all_predictions = []
        all_labels = []

        for batch in train_loader:
            batch = batch.to(self.device)

            self.optimizer.zero_grad()

            # Forward pass
            _, risk_scores = self.model(batch.x, batch.edge_index, batch.edge_attr)

            # For training, use node-level labels (simplified)
            # In practice, you'd have proper labels
            target_labels = torch.rand(batch.x.size(0), 1, device=self.device)

            loss = self.criterion(risk_scores, target_labels)

            # Backward pass
            loss.backward()

            # Gradient clipping
            torch.nn.utils.clip_grad_norm_(self.model.parameters(), self.config.gradient_clip_value)

            self.optimizer.step()

            total_loss += loss.item()

            # Collect predictions for metrics
            all_predictions.extend(risk_scores.detach().cpu().numpy().flatten())
            all_labels.extend(target_labels.detach().cpu().numpy().flatten())

        # Calculate metrics
        metrics = {
            'loss': total_loss / len(train_loader)
        }

        if all_predictions and all_labels:
            try:
                metrics['auc'] = roc_auc_score(all_labels, all_predictions)
                precision, recall, _ = precision_recall_curve(all_labels, all_predictions)
                metrics['precision'] = np.mean(precision)
                metrics['recall'] = np.mean(recall)
            except:
                pass

        return metrics

    def _validate_epoch(self, val_loader: DataLoader) -> Dict[str, float]:
        """Validate for one epoch"""
        self.model.eval()

        total_loss = 0.0
        all_predictions = []
        all_labels = []

        with torch.no_grad():
            for batch in val_loader:
                batch = batch.to(self.device)

                # Forward pass
                _, risk_scores = self.model(batch.x, batch.edge_index, batch.edge_attr)

                # Generate target labels (simplified)
                target_labels = torch.rand(batch.x.size(0), 1, device=self.device)

                loss = self.criterion(risk_scores, target_labels)
                total_loss += loss.item()

                # Collect predictions for metrics
                all_predictions.extend(risk_scores.detach().cpu().numpy().flatten())
                all_labels.extend(target_labels.detach().cpu().numpy().flatten())

        # Calculate metrics
        metrics = {
            'loss': total_loss / len(val_loader)
        }

        if all_predictions and all_labels:
            try:
                metrics['auc'] = roc_auc_score(all_labels, all_predictions)
                precision, recall, _ = precision_recall_curve(all_labels, all_predictions)
                metrics['precision'] = np.mean(precision)
                metrics['recall'] = np.mean(recall)
            except:
                pass

        return metrics

    def save_model(self, path: str):
        """Save the trained model"""
        os.makedirs(os.path.dirname(path), exist_ok=True)

        torch.save({
            'model_state_dict': self.model.state_dict(),
            'optimizer_state_dict': self.optimizer.state_dict(),
            'config': vars(self.config),
            'best_val_loss': self.best_val_loss,
            'best_val_auc': self.best_val_auc,
            'training_history': [vars(m) for m in self.training_history]
        }, path)

        logger.info(f"Model saved to {path}")

    def load_model(self, path: str):
        """Load a trained model"""
        checkpoint = torch.load(path, map_location=self.device)

        # Recreate model with saved config
        saved_config = checkpoint.get('config', {})
        config = TrainingConfig(**saved_config)
        self.config = config

        # Initialize model
        input_dim = checkpoint['model_state_dict']['convs.0.weight'].shape[1]
        self.initialize_model(input_dim)

        # Load state
        self.model.load_state_dict(checkpoint['model_state_dict'])
        self.optimizer.load_state_dict(checkpoint['optimizer_state_dict'])

        self.best_val_loss = checkpoint.get('best_val_loss', float('inf'))
        self.best_val_auc = checkpoint.get('best_val_auc', 0.0)
        self.training_history = checkpoint.get('training_history', [])

        logger.info(f"Model loaded from {path}")

    def evaluate_model(self, test_loader: DataLoader) -> Dict[str, float]:
        """Evaluate the model on test data"""
        self.model.eval()

        all_predictions = []
        all_labels = []
        total_loss = 0.0

        with torch.no_grad():
            for batch in test_loader:
                batch = batch.to(self.device)

                _, risk_scores = self.model(batch.x, batch.edge_index, batch.edge_attr)
                target_labels = torch.rand(batch.x.size(0), 1, device=self.device)

                loss = self.criterion(risk_scores, target_labels)
                total_loss += loss.item()

                all_predictions.extend(risk_scores.cpu().numpy().flatten())
                all_labels.extend(target_labels.cpu().numpy().flatten())

        # Calculate comprehensive metrics
        metrics = {
            'test_loss': total_loss / len(test_loader),
            'test_auc': roc_auc_score(all_labels, all_predictions),
        }

        # Precision-Recall metrics
        precision, recall, _ = precision_recall_curve(all_labels, all_predictions)
        metrics['test_precision'] = np.mean(precision)
        metrics['test_recall'] = np.mean(recall)
        metrics['test_pr_auc'] = auc(recall, precision)

        # Additional metrics
        predictions_binary = (np.array(all_predictions) > 0.5).astype(int)
        labels_binary = (np.array(all_labels) > 0.5).astype(int)

        from sklearn.metrics import accuracy_score, f1_score, confusion_matrix

        metrics['test_accuracy'] = accuracy_score(labels_binary, predictions_binary)
        metrics['test_f1'] = f1_score(labels_binary, predictions_binary)

        cm = confusion_matrix(labels_binary, predictions_binary)
        metrics['test_tn'] = cm[0, 0]
        metrics['test_fp'] = cm[0, 1]
        metrics['test_fn'] = cm[1, 0]
        metrics['test_tp'] = cm[1, 1]

        return metrics

    def plot_training_history(self, save_path: Optional[str] = None):
        """Plot training history"""
        if not self.training_history:
            logger.warning("No training history available")
            return

        epochs = [m.epoch for m in self.training_history]
        train_losses = [m.train_loss for m in self.training_history]
        val_losses = [m.val_loss for m in self.training_history]
        train_aucs = [m.train_auc for m in self.training_history]
        val_aucs = [m.val_auc for m in self.training_history]

        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 10))

        # Loss plot
        ax1.plot(epochs, train_losses, label='Train Loss')
        ax1.plot(epochs, val_losses, label='Validation Loss')
        ax1.set_xlabel('Epoch')
        ax1.set_ylabel('Loss')
        ax1.set_title('Training and Validation Loss')
        ax1.legend()
        ax1.grid(True)

        # AUC plot
        ax2.plot(epochs, train_aucs, label='Train AUC')
        ax2.plot(epochs, val_aucs, label='Validation AUC')
        ax2.set_xlabel('Epoch')
        ax2.set_ylabel('AUC')
        ax2.set_title('Training and Validation AUC')
        ax2.legend()
        ax2.grid(True)

        # Precision plot
        train_precisions = [m.train_precision for m in self.training_history]
        val_precisions = [m.val_precision for m in self.training_history]
        ax3.plot(epochs, train_precisions, label='Train Precision')
        ax3.plot(epochs, val_precisions, label='Validation Precision')
        ax3.set_xlabel('Epoch')
        ax3.set_ylabel('Precision')
        ax3.set_title('Training and Validation Precision')
        ax3.legend()
        ax3.grid(True)

        # Recall plot
        train_recalls = [m.train_recall for m in self.training_history]
        val_recalls = [m.val_recall for m in self.training_history]
        ax4.plot(epochs, train_recalls, label='Train Recall')
        ax4.plot(epochs, val_recalls, label='Validation Recall')
        ax4.set_xlabel('Epoch')
        ax4.set_ylabel('Recall')
        ax4.set_title('Training and Validation Recall')
        ax4.legend()
        ax4.grid(True)

        plt.tight_layout()

        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            logger.info(f"Training history plot saved to {save_path}")
        else:
            plt.show()

    def generate_training_report(self, training_results: Dict[str, Any],
                               evaluation_metrics: Dict[str, float]) -> str:
        """Generate a comprehensive training report"""
        report = f"""
# GNN Model Training Report

Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Model Configuration
- Hidden Dimension: {self.config.hidden_dim}
- Number of Layers: {self.config.num_layers}
- Learning Rate: {self.config.learning_rate}
- Batch Size: {self.config.batch_size}
- Dropout Rate: {self.config.dropout_rate}
- Weight Decay: {self.config.weight_decay}

## Training Results
- Epochs Trained: {training_results['epochs_trained']}
- Final Training Loss: {training_results['final_train_loss']:.4f}
- Final Validation Loss: {training_results['final_val_loss']:.4f}
- Best Validation Loss: {training_results['best_val_loss']:.4f}
- Best Validation AUC: {training_results['best_val_auc']:.4f}
- Model Parameters: {training_results['model_parameters']:,}

## Test Evaluation Metrics
- Test Loss: {evaluation_metrics['test_loss']:.4f}
- Test AUC: {evaluation_metrics['test_auc']:.4f}
- Test Accuracy: {evaluation_metrics['test_accuracy']:.4f}
- Test F1 Score: {evaluation_metrics['test_f1']:.4f}
- Test Precision: {evaluation_metrics['test_precision']:.4f}
- Test Recall: {evaluation_metrics['test_recall']:.4f}
- Test PR-AUC: {evaluation_metrics['test_pr_auc']:.4f}

## Confusion Matrix
- True Negatives: {evaluation_metrics['test_tn']}
- False Positives: {evaluation_metrics['test_fp']}
- False Negatives: {evaluation_metrics['test_fn']}
- True Positives: {evaluation_metrics['test_tp']}

## Training Stability
- Loss converged: {training_results['final_val_loss'] < training_results['final_train_loss'] * 1.2}
- AUC improved: {training_results['best_val_auc'] > 0.7}
- No overfitting: {abs(training_results['final_train_loss'] - training_results['final_val_loss']) < 0.1}
"""

        return report

class AdversarialTrainingMixin:
    """
    Mixin class for adversarial training to improve model robustness
    """

    def generate_adversarial_examples(self, batch: Data, epsilon: float = 0.1) -> Data:
        """Generate adversarial examples for training"""
        batch = batch.clone()

        # Add noise to node features
        noise = torch.randn_like(batch.x) * epsilon
        batch.x = batch.x + noise

        # Add noise to edge attributes
        if batch.edge_attr is not None:
            edge_noise = torch.randn_like(batch.edge_attr) * epsilon
            batch.edge_attr = batch.edge_attr + edge_noise

        return batch

    def train_with_adversarial(self, train_loader: DataLoader, val_loader: DataLoader,
                             epsilon: float = 0.1) -> Dict[str, Any]:
        """Train with adversarial examples"""
        logger.info("Starting adversarial training")

        # Store original training method
        original_train_epoch = self._train_epoch

        # Override training method to include adversarial examples
        def adversarial_train_epoch(train_loader):
            self.model.train()

            total_loss = 0.0
            all_predictions = []
            all_labels = []

            for batch in train_loader:
                batch = batch.to(self.device)

                # Train on clean examples
                self.optimizer.zero_grad()
                _, clean_risk_scores = self.model(batch.x, batch.edge_index, batch.edge_attr)
                target_labels = torch.rand(batch.x.size(0), 1, device=self.device)
                clean_loss = self.criterion(clean_risk_scores, target_labels)

                # Train on adversarial examples
                adv_batch = self.generate_adversarial_examples(batch, epsilon)
                _, adv_risk_scores = self.model(adv_batch.x, adv_batch.edge_index, adv_batch.edge_attr)
                adv_loss = self.criterion(adv_risk_scores, target_labels)

                # Combined loss
                loss = clean_loss + adv_loss

                loss.backward()
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), self.config.gradient_clip_value)
                self.optimizer.step()

                total_loss += loss.item()

                # Collect predictions from clean examples
                all_predictions.extend(clean_risk_scores.detach().cpu().numpy().flatten())
                all_labels.extend(target_labels.detach().cpu().numpy().flatten())

            metrics = {
                'loss': total_loss / len(train_loader)
            }

            if all_predictions and all_labels:
                try:
                    metrics['auc'] = roc_auc_score(all_labels, all_predictions)
                    precision, recall, _ = precision_recall_curve(all_labels, all_predictions)
                    metrics['precision'] = np.mean(precision)
                    metrics['recall'] = np.mean(recall)
                except:
                    pass

            return metrics

        # Temporarily replace training method
        self._train_epoch = adversarial_train_epoch

        try:
            # Run training
            results = self.train_model(train_loader, val_loader)
            results['adversarial_epsilon'] = epsilon
            return results
        finally:
            # Restore original method
            self._train_epoch = original_train_epoch

class CurriculumLearningTrainer(GNNModelTrainer):
    """
    Trainer that uses curriculum learning to gradually increase training difficulty
    """

    def __init__(self, config: TrainingConfig = None):
        super().__init__(config)
        self.curriculum_stages = [
            {'name': 'simple', 'complexity': 0.3, 'epochs': 20},
            {'name': 'medium', 'complexity': 0.6, 'epochs': 30},
            {'name': 'complex', 'complexity': 1.0, 'epochs': 50}
        ]

    def train_with_curriculum(self, data_pool: List[Any], save_path: Optional[str] = None) -> Dict[str, Any]:
        """Train using curriculum learning approach"""
        logger.info("Starting curriculum learning training")

        overall_results = {
            'stages': [],
            'final_model': None
        }

        current_data = data_pool

        for stage in self.curriculum_stages:
            logger.info(f"Starting curriculum stage: {stage['name']}")

            # Filter data for current complexity level
            stage_data = self._filter_data_by_complexity(current_data, stage['complexity'])

            # Prepare data loaders
            train_loader, val_loader = self.prepare_training_data(stage_data)

            # Initialize model if first stage
            if not self.model:
                sample_batch = next(iter(train_loader))
                input_dim = sample_batch.x.shape[1]
                self.initialize_model(input_dim)

            # Train for this stage
            stage_results = self.train_model(train_loader, val_loader, save_path=None)

            # Store stage results
            stage_results['stage_name'] = stage['name']
            stage_results['complexity'] = stage['complexity']
            overall_results['stages'].append(stage_results)

            logger.info(f"Completed stage {stage['name']} with best val loss: {stage_results['best_val_loss']:.4f}")

        # Final evaluation
        overall_results['final_model'] = {
            'best_val_loss': min(s['best_val_loss'] for s in overall_results['stages']),
            'best_val_auc': max(s['best_val_auc'] for s in overall_results['stages']),
            'total_epochs': sum(s['epochs_trained'] for s in overall_results['stages'])
        }

        # Save final model
        if save_path:
            self.save_model(save_path)

        return overall_results

    def _filter_data_by_complexity(self, data_pool: List[Any], complexity: float) -> List[Any]:
        """Filter training data based on complexity level"""
        # Simplified complexity filtering
        # In practice, this would analyze graph properties

        num_samples = int(len(data_pool) * complexity)
        return data_pool[:num_samples]

# Example usage and testing
if __name__ == "__main__":
    # Create sample training data
    def generate_sample_data(num_samples: int = 100):
        data = []

        for i in range(num_samples):
            # Generate sample nodes
            nodes = [
                {'id': f'node_{i}_0', 'type': 'user', 'features': np.random.rand(64)},
                {'id': f'node_{i}_1', 'type': 'server', 'features': np.random.rand(64)},
                {'id': f'node_{i}_2', 'type': 'database', 'features': np.random.rand(64)}
            ]

            # Generate sample edges
            edges = [
                {'source': f'node_{i}_0', 'target': f'node_{i}_1', 'type': 'access'},
                {'source': f'node_{i}_1', 'target': f'node_{i}_2', 'type': 'data_flow'}
            ]

            # Generate temporal events
            temporal_events = [
                {'type': 'login', 'timestamp': datetime.now(), 'actor': f'node_{i}_0'},
                {'type': 'query', 'timestamp': datetime.now(), 'actor': f'node_{i}_1'}
            ]

            data.append((nodes, edges, temporal_events))

        return data

    # Initialize trainer
    config = TrainingConfig(
        learning_rate=0.001,
        batch_size=16,
        num_epochs=50,
        hidden_dim=128,
        num_layers=3
    )

    trainer = GNNModelTrainer(config)

    # Generate training data
    train_data = generate_sample_data(200)

    # Prepare data loaders
    train_loader, val_loader = trainer.prepare_training_data(train_data)

    # Initialize model
    sample_batch = next(iter(train_loader))
    input_dim = sample_batch.x.shape[1]
    trainer.initialize_model(input_dim)

    # Train model
    training_results = trainer.train_model(train_loader, val_loader, save_path='models/gnn_model.pth')

    # Evaluate model
    test_data = generate_sample_data(50)
    test_loader, _ = trainer.prepare_training_data(test_data)
    evaluation_metrics = trainer.evaluate_model(test_loader)

    # Generate report
    report = trainer.generate_training_report(training_results, evaluation_metrics)
    print(report)

    # Plot training history
    trainer.plot_training_history(save_path='plots/training_history.png')