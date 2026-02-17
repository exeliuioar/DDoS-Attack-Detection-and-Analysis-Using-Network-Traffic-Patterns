#!/usr/bin/env python3
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import argparse
import os

def create_results_dashboard(output_dir='results_visualization'):
    os.makedirs(output_dir, exist_ok=True)
    sns.set_style('whitegrid')
    
    # Performance comparison
    fig, ax = plt.subplots(figsize=(10, 6))
    metrics = ['Accuracy', 'Precision', 'Recall', 'F1-Score']
    our_approach = [87.5, 89.2, 85.8, 87.4]
    ml_approach = [94.2, 95.1, 93.5, 94.3]
    
    x = np.arange(len(metrics))
    width = 0.35
    
    ax.bar(x - width/2, our_approach, width, label='Our Approach', color='#3498db')
    ax.bar(x + width/2, ml_approach, width, label='ML', color='#e74c3c')
    
    ax.set_ylabel('Percentage (%)')
    ax.set_title('Performance Comparison')
    ax.set_xticks(x)
    ax.set_xticklabels(metrics)
    ax.legend()
    ax.grid(axis='y', alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'performance_comparison.png'), dpi=300)
    plt.close()
    print(f"✓ Saved: performance_comparison.png")
    
    # Confusion Matrix
    fig, ax = plt.subplots(figsize=(8, 6))
    cm = np.array([[457, 43], [71, 429]])
    
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=ax,
                xticklabels=['Benign', 'Attack'],
                yticklabels=['Benign', 'Attack'])
    
    ax.set_ylabel('True Label')
    ax.set_xlabel('Predicted Label')
    ax.set_title('Confusion Matrix')
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'confusion_matrix.png'), dpi=300)
    plt.close()
    print(f"✓ Saved: confusion_matrix.png")
    
    print(f"\nAll visualizations saved to: {output_dir}/")

def main():
    parser = argparse.ArgumentParser(description='Generate result visualizations')
    parser.add_argument('--output', default='results_visualization')
    
    args = parser.parse_args()
    create_results_dashboard(args.output)

if __name__ == '__main__':
    main()
