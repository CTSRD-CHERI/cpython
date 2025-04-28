" .vimrc in your project directory
"––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––

" 1) Tell Vim where to find your tags
"    - look for a file named “tags” in the cwd or any parent dir
set tags=ctags/tags;/


" 2) If there’s a cscope.out in the cwd, add it
if filereadable("cscope/cscope.out")
	" -d = don’t rebuild, -q = enable quick symbol lookup
  cs add cscope/cscope.out
endif

