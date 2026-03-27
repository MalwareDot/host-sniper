from host_sniper import handler
import builtins
inputs = iter(['example.com', '443'])
setattr(builtins, 'input', lambda prompt='': next(inputs))
handler.run_ssl_analysis()
