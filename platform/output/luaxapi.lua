
local XAPI = {}
local h2b = {
	["0"] = 0,
	["1"] = 1,
	["2"] = 2,
	["3"] = 3,
	["4"] = 4,
	["5"] = 5,
	["6"] = 6,
	["7"] = 7,
	["8"] = 8,
	["9"] = 9,
	["A"] = 10,
	["B"] = 11,
	["C"] = 12,
	["D"] = 13,
	["E"] = 14,
	["F"] = 15,
	["a"] = 10,
	["b"] = 11,
	["c"] = 12,
	["d"] = 13,
	["e"] = 14,
	["f"] = 15
}

function XAPI:bin2hex(s)
    s=string.gsub(s,"(.)",function (x) return string.format("%02X ",string.byte(x)) end)
    return s
end

function XAPI:hex2bin( hexstr )
    local s = string.gsub(hexstr, "(.)(.)%s", function ( h, l )
         return string.char(h2b[h]*16+h2b[l])
    end)
    return s
end

--split string to table
function XAPI:split(s, delim)
    if type(delim) ~= "string" or string.len(delim) <= 0 then
        return
    end
    local start = 1
    local t = {}
    while true do
    local pos = string.find (s, delim, start, true) -- plain find
        if not pos then
          break
        end
        table.insert (t, string.sub (s, start, pos - 1))
        start = pos + string.len (delim)
    end
    table.insert (t, string.sub (s, start))
    return t
end

--LUA数据表打印
local key = ""
function XAPI:PrintTable(table, level)
  level = level or 1
  local indent = ""
  for i = 1, level do
    indent = indent.."  "
  end
  if key ~= "" then
    print(indent..key.." ".."=".." ".."{")
  else
    print(indent .. "{")
  end
  key = ""
  for k,v in pairs(table) do
     if type(v) == "table" then
        key = k
        XAPI:PrintTable(v, level + 1)
     else
        local content = string.format("%s%s = %s", indent .. "  ",tostring(k), tostring(v))
		print(content)
      end
  end
  print(indent .. "}")
end

function XAPI:checkSum( data, len )
	if string.byte(data,1) ~= 0xAA  then
		return false
	end
	local nAdds  = 0
	local chksum =  string.byte(data,len-2) + string.byte(data,len-1)*256
	for i = 2, len - 3, 1 do
		nAdds = nAdds + string.byte(data,i)
	end
	if nAdds%0xFFFF == chksum then
		return true
	end
	return false
end

function XAPI:new(args)
   local new = { }
   if args then
      for key, val in pairs(args) do
         new[key] = val
      end
   end
   return setmetatable(new, XAPI)
end

XAPI.__index = XAPI
return XAPI:new()
