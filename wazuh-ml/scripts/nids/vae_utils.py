"""vae_utils.py - Custom layers for VAE models"""

import tensorflow as tf
from tensorflow.keras import layers


@tf.keras.utils.register_keras_serializable(package='NIDS')
class Sampling(layers.Layer):
    """Reparameterization trick for VAE: z = z_mean + exp(0.5 * z_log_var) * epsilon"""
    
    def call(self, inputs):
        z_mean, z_log_var = inputs
        eps = tf.random.normal(shape=tf.shape(z_mean))
        return z_mean + tf.exp(0.5 * z_log_var) * eps
    
    def get_config(self):
        return super().get_config()
