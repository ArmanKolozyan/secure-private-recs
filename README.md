# Experimenting with Nudge

This repository is a fork of [Nudge](https://github.com/NudgeArtifact/private-recs), a privacy-preserving recommendations engine. The corresponding paper (titled "Nudge: A Private Recommendations Engine") by Alexandra Henzinger, Emma Dauterman, Henry Corrigan-Gibbs and Dan Boneh is accessible [here](https://eprint.iacr.org/2026/179.pdf).

In this repo, I experiment with attacks on Nudge's training when one of the servers is malicious and deviates from the protocol (which is outside Nudge's threat model). The goal is to motivate the need for maliciously secure private recommendation systems. The attack code is in `attacks/`.
