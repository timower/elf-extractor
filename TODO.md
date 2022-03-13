 * PIC refs cross BBs
  --> angr / smarted reg state
 * PIC ref got

 * GOT reg through stack spill

 * jump tables
  cmp r4, #8
  addls pc, pc, r4, lsl #2
  b ..
; table:
  b ..
  b ..
  ..
