## Test output

```
Running mock tests for AnomalyWizard...

[TEST] send_alert(1.2.3.4, 1200)
Alert triggered: True

Private IP alerted: False

[TEST] send_alert(1.2.3.6, 600) at 1777805536.2008355
Alerts before/after immediate repeat: 1 1

Done.
```

## Explaination
1. The first line:
`[TEST] send_alert(1.2.3.4, 1200)`

 means the simulated packet stream for destination 1.2.3.4 crossed the alert threshold in test_monitor.py. 
 
- The next line:
 `Alert triggered: True`

 confirms the test detected that spike and called the alert path.

2. `Private IP alerted: False`

 means the code correctly ignored traffic to 192.168.1.100, which is a private LAN address and should not trigger a threat alert.

3. `[TEST] send_alert(1.2.3.6, 600) at ... `

shows the alert fired once for a second public IP.

`Alerts before/after immediate repeat: 1 1 `

means the cooldown logic worked: sending more packets immediately after the first alert did not create a second alert.
