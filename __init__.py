from binaryninja import *
import logging



# Binary Ninja does not assume types to be character arrays and initializes them void.
# This plugin analyzes the selected function for character arrays and re-declares them 
# as such, eg. (char buff[size]). Show strings as is on your pane and not as void types
# if like me, this is your preferance.
#
# In an attempt to cooperate with other architectures, the majority of checks are done with the MLIL.
# Functions could also be checked with HLIL get_var_uses()
#
# Tested on CTF challenges from coorporate cyber challenges and https://pwnable.tw/challenge/.
# MIT License 2023


def withComments(bv, function):
	analyze_voids(bv,function,1)


def withTags(bv,function):
	analyze_voids(bv,function,2)


def withBoth(bv,function):
	analyze_voids(bv, function,3)


def change_types(bv,variables,function,opt):
	modified_var_names = ""
	for var in variables:
		size = abs(var.storage-function.stack_layout[function.stack_layout.index(var)+1].storage)
		new_type = Type.array(Type.char(), size)
		var.set_type_async(new_type)
		modified_var_names += var.name+", "
		addr = function.high_level_il.get_var_uses(var)[0].address
		if opt == 1 or opt == 3:
			bv.set_comment_at(addr, "Assumed char[] | "+str(size)+" bytes | Pos "+str(function.stack_layout.index(var)))
			#log_info("Wrote comment @ "+str(hex(addr)))
		if opt == 2 or opt == 3:
			#log_info("Wrote tag @ "+str(hex(addr)))
			tt = bv.create_tag_type("Char Arrays Plugin","ℹ️")
			bv.create_auto_data_tag(addr, tt, "Assumed char[] | "+str(size)+" bytes | Pos "+str(function.stack_layout.index(var))+" | Declared before "+function.stack_layout[function.stack_layout.index(var)+1].name)
	function.reanalyze()
	if len(modified_var_names) < 1:
		log_info("(Nothing to Retype) No char arrays found in function!","Char Arrays Plugin")
		return
	log_info("(Success) Retyped the following: "+modified_var_names[:-2], "Char Arrays Plugin")


def analyze_voids(bv,function, *arg):

	possible_vars = []
	likely_vars = []

	for v in function.stack_layout:
		if type(v.type) == types.VoidType and v.last_seen_name[:4] == "var_":
			possible_vars.append(v)
	if not possible_vars:
		log_info("(No Valid Vars) No possible variables found!","Char Arrays Plugin")
		return

	mlil = []
	for b in function.medium_level_il.basic_blocks:
		mlil += b.disassembly_text
	
	def analyze_calls(update):
		max = len(function.callees)*len(possible_vars)
		curr = 0
		for v in possible_vars:
			for c in function.callees:
				found = 0
				for idx, i in enumerate(mlil):
					if c.name == str(i.tokens[0]):
						for j in range(1,len(c.parameter_vars)):
							tokens = mlil[idx-j].tokens
							if v.last_seen_name in str(tokens):
								found = 1
								break
						if found == 1:
							break
				curr += 1
				update(curr,max)
				if found == 1:
					curr += (len(function.callees) - function.callees.index(c))
					likely_vars.append(v)
					break
			curr += int(len(function.callees)/len(possible_vars))
			update(curr,max)
			
	
	task = run_progress_dialog("Analyzing Calls... (Char Arrays Plugin)", True, analyze_calls)
		
	if task:
		if len(arg) > 0:
			change_types(bv, likely_vars, function, arg[0])
		else:
			change_types(bv, likely_vars, function, 0)
	else:
		log_info("(User Cancel) Cancelled analysis!","Char Arrays Plugin")


logging.disable(logging.WARNING)
PluginCommand.register_for_function("Find Char Arrays\\0 Define", "Analyze void variables and load as defined character arrays.", analyze_voids)
PluginCommand.register_for_function("Find Char Arrays\\1 Define with comments", "Analyze void variables and load as defined character arrays with comments.", withComments)
PluginCommand.register_for_function("Find Char Arrays\\2 Define with tags", "Analyze void variables and load as defined character arrays with comments.", withTags)
PluginCommand.register_for_function("Find Char Arrays\\3 Define with both", "Analyze void variables and load as defined character arrays with comments.", withBoth)

