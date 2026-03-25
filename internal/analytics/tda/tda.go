// Package tda provides topological data analysis for vulnerability clustering.
//
// It uses persistent homology (0-dimensional) to identify stable clusters of
// cryptographic findings that share similar characteristics. The Vietoris-Rips
// filtration tracks connected components as the distance threshold increases,
// and the resulting persistence diagram reveals which clusters are robust
// features versus noise.
package tda
