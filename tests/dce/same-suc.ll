@.str = private unnamed_addr constant [14 x i8] c"Hello world!\0A\00", align 1

define dso_local i32 @main(i32 %argc, ptr %argv) {
; CHECK-LABEL: define dso_local i32 @main
; CHECK-SAME: (i32 [[ARGC:%.*]], ptr [[ARGV:%.*]]) {
; CHECK-NEXT:  cond.end:
; CHECK-NEXT:    [[CALL:%.*]] = call i32 (ptr, ...) @printf(ptr @.str)
; CHECK-NEXT:    ret i32 0
;
entry:
  %add = add nsw i32 %argc, 42
  %mul = mul nsw i32 %add, 2
  %cmp = icmp sgt i32 %mul, 0
  br i1 %cmp, label %cond.end, label %cond.end

cond.end:                                         ; preds = %cond.false, %cond.true
  %call = call i32 (ptr, ...) @printf(ptr @.str)
  ret i32 0
}

declare dso_local i32 @printf(ptr, ...)
