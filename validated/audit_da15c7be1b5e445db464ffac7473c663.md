Looking at the external bug class: a token serving dual roles (staked balance holder + reward recipient) causes the balance used in reward calculation to be inflated by reward distributions, leading to incorrect reward allocation.

I need to trace this through Kaia's reward and staking modules.