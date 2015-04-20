// The max height for any divtoggle div.
var maxheight = 150;

// Process a Show More/Less request
function toggleDescriptionVis(elem) {
	var targetdiv = $(elem).parent().find(".divtoggle")
    if($(targetdiv).hasClass('hide')) {
        $(targetdiv).show().removeClass('hide');
        $(elem).html('<br />Show Less...');
    } 
    else {             
      	$(targetdiv).hide().addClass('hide');
        $(elem).html('Show More...');
    }
}

// Called on document.ready to compress overly large divs
function formatDescriptions() {
	$(".divtoggle").each(function () {
		if ($(this).height() > maxheight) {
		        $(this).hide().addClass('hide');
		        $(this).parent().find(".toggle").show().html('Show More...');
		}			
	});
}

// Process a checkbox change
function checkboxChange(cb, severity) {
	if (cb.checked) {
		$("." + severity).parent().show();
	}
	else {
		$("." + severity).parent().hide();
	}
}

// Check all the boxes & mark elements visible
function checkTheBoxes() {
    $(".cb").each(function() {
    	this.checked = true;
    });
    // Not sure why this doesn't work $(".critical .high .medium .low .info").parent().show();
    $(".critical").parent().show();
    $(".high").parent().show();
    $(".medium").parent().show();
    $(".low").parent().show();
    $(".info").parent().show();
}   

function showLoading() {
    $("#loading").show();
}

// ********************* PAGE READY *********************
$(function() {
	formatDescriptions();
    checkTheBoxes();

    $("#showeverything").click(function() {
    	checkTheBoxes();
    });

    $(".toggle").click(function(){
      toggleDescriptionVis(this);
    }); 

    $(".hideme").each(function () {
        $(this).hide();
    });

    $("#formatting").show();
    $("#accordion").accordion({
        heightStyle: "content",
        collapsible: "true",
        active: "false",
        create: function (event, ui) {
            //setIcons();
        }
    });
    $("#formatting").hide();

    var uniques = [];
    var patt = /^\[/;
    $("#accordion h6").each(function(index){
    	if (patt.test($(this).text())) {
        	var arr = $(this).text().match(/\[[a-zA-Z\s]+\]/).sort().forEach(function(entry) {
        		var text = entry.replace('[','').replace(']','');
        		if ($.inArray(text, uniques) == -1){
        	 		$("#selectcategory").append("<option value='" + text + "'>" + text + "</option>");
        	 		uniques.push(text)
        	 	}	
        	});
    	}
    });

    function hidefindings(label) {
		$("#accordion h6:not(:contains('[" + label + "]'))").hide();
    	$("#accordion h6:contains('[" + label + "]')").show();
    }

	$("#selectcategory").selectmenu({
		change: function(event, ui) { hidefindings(ui.item.value); }
	});

	var selectList = $('#selectcategory option');
	selectList.sort(function(a,b){
	    a = a.value;
	    b = b.value;
	 
	    return a-b;
	});
	
	$("#selectcategory").eq(0).html(selectList);

    
});