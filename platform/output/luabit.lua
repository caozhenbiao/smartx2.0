BIT={data32={}}
for i=1,32 do
	BIT.data32[i]=2^(32-i)
end

function BIT:d2b(arg)
	local   tr={}
	for i=1,32 do
		if arg >= self.data32[i] then
			tr[i]=1
			arg=arg-self.data32[i]
		else
			tr[i]=0
		end
	end
	return   tr
end   --BIT:d2b

function BIT:b2d(arg)
	local   nr=0
	for i=1,32 do
		if arg[i] ==1 then
			nr=nr+2^(32-i)
		end
	end
	return  nr
end   --BIT:b2d

function BIT:_xor(a,b)
	local   op1=self:d2b(a)
	local   op2=self:d2b(b)
	local   r={}

	for i=1,32 do
		if op1[i]==op2[i] then
			r[i]=0
		else
			r[i]=1
		end
	end
	return  self:b2d(r)
end --BIT:xor

function BIT:_and(a,b)
	local   op1=self:d2b(a)
	local   op2=self:d2b(b)
	local   r={}

	for i=1,32 do
		if op1[i]==1 and op2[i]==1  then
			r[i]=1
		else
			r[i]=0
		end
	end
	return  self:b2d(r)

end --BIT:_and

function    BIT:_or(a,b)
	local   op1=self:d2b(a)
	local   op2=self:d2b(b)
	local   r={}

	for i=1,32 do
		if  op1[i]==1 or   op2[i]==1   then
			r[i]=1
		else
			r[i]=0
		end
	end
	return  self:b2d(r)
end --BIT:_or

function BIT:_not(a)
	local   op1=self:d2b(a)
	local   r={}

	for i=1,32 do
		if  op1[i]==1   then
			r[i]=0
		else
			r[i]=1
		end
	end
	return  self:b2d(r)
end --BIT:_not

function BIT:_rshift(a,n)
	local   op1=self:d2b(a)
	local   r=self:d2b(0)

	if n < 32 and n > 0 then
		for i=1,n do
			for i=31,1,-1 do
				op1[i+1]=op1[i]
			end
			op1[1]=0
		end
		r=op1
	end
	return  self:b2d(r)
end --BIT:_rshift

function BIT:_lshift(a,n)
	local   op1=self:d2b(a)
	local   r=self:d2b(0)

	if n < 32 and n > 0 then
		for i=1,n   do
			for i=1,31 do
				op1[i]=op1[i+1]
			end
			op1[32]=0
		end
		r=op1
	end
	return  self:b2d(r)
end --BIT:_lshift


function BIT:print(ta)
	local   sr=""
	for i=1,32 do
		sr=sr..ta[i]
	end
	print(sr)
end


